#!/usr/bin/env python3
"""
Enhanced Secret Detection Patterns
Comprehensive regex patterns for detecting various types of secrets and credentials
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class SecretPattern:
    """Pattern definition for secret detection"""
    name: str
    pattern: str
    severity: str  # critical, high, medium, low
    description: str
    regex: re.Pattern = None
    
    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE)


# AWS Credentials
AWS_PATTERNS = [
    SecretPattern(
        name="AWS Access Key ID",
        pattern=r'(AKIA[0-9A-Z]{16})',
        severity="critical",
        description="AWS Access Key ID"
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        severity="critical",
        description="AWS Secret Access Key"
    ),
    SecretPattern(
        name="AWS Session Token",
        pattern=r'(ASIA[0-9A-Z]{16})',
        severity="critical",
        description="AWS Session Token"
    ),
    SecretPattern(
        name="AWS Account ID",
        pattern=r'aws[_-]?account[_-]?id\s*[=:]\s*["\']?(\d{12})["\']?',
        severity="medium",
        description="AWS Account ID"
    ),
]

# Private Keys
PRIVATE_KEY_PATTERNS = [
    SecretPattern(
        name="RSA Private Key",
        pattern=r'-----BEGIN RSA PRIVATE KEY-----',
        severity="critical",
        description="RSA Private Key"
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=r'-----BEGIN EC PRIVATE KEY-----',
        severity="critical",
        description="Elliptic Curve Private Key"
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
        severity="critical",
        description="OpenSSH Private Key"
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        severity="critical",
        description="PGP Private Key"
    ),
    SecretPattern(
        name="DSA Private Key",
        pattern=r'-----BEGIN DSA PRIVATE KEY-----',
        severity="critical",
        description="DSA Private Key"
    ),
]

# JWT Tokens
JWT_PATTERNS = [
    SecretPattern(
        name="JWT Token",
        pattern=r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        severity="high",
        description="JSON Web Token"
    ),
]

# API Keys  
API_KEY_PATTERNS = [
    SecretPattern(
        name="Generic API Key",
        pattern=r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
        severity="high",
        description="Generic API Key"
    ),
    SecretPattern(
        name="Slack Token",
        pattern=r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
        severity="critical",
        description="Slack API Token"
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}',
        severity="high",
        description="Slack Webhook URL"
    ),
    SecretPattern(
        name="Stripe API Key",
        pattern=r'(?:sk|pk)_live_[0-9a-zA-Z]{24,}',
        severity="critical",
        description="Stripe API Key"
    ),
    SecretPattern(
        name="Stripe Restricted Key",
        pattern=r'rk_live_[0-9a-zA-Z]{24,}',
        severity="high",
        description="Stripe Restricted Key"
    ),
    SecretPattern(
        name="Square Access Token",
        pattern=r'sq0atp-[0-9A-Za-z\-_]{22}',
        severity="critical",
        description="Square Access Token"
    ),
    SecretPattern(
        name="Square OAuth Secret",
        pattern=r'sq0csp-[0-9A-Za-z\-_]{43}',
        severity="critical",
        description="Square OAuth Secret"
    ),
    SecretPattern(
        name="PayPal Braintree Token",
        pattern=r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        severity="critical",
        description="PayPal Braintree Access Token"
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=r'SK[0-9a-fA-F]{32}',
        severity="critical",
        description="Twilio API Key"
    ),
]

# Google Cloud / Firebase
GOOGLE_PATTERNS = [
    SecretPattern(
        name="Google API Key",
        pattern=r'AIza[0-9A-Za-z\-_]{35}',
        severity="high",
        description="Google API Key"
    ),
    SecretPattern(
        name="Google OAuth",
        pattern=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        severity="high",
        description="Google OAuth Client ID"
    ),
    SecretPattern(
        name="Firebase URL",
        pattern=r'.*firebaseio\.com',
        severity="medium",
        description="Firebase Database URL"
    ),
]

# GitHub
GITHUB_PATTERNS = [
    SecretPattern(
        name="GitHub Token",
        pattern=r'gh[pousr]_[A-Za-z0-9_]{36,}',
        severity="critical",
        description="GitHub Personal Access Token"
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        pattern=r'gho_[A-Za-z0-9_]{36,}',
        severity="critical",
        description="GitHub OAuth Token"
    ),
    SecretPattern(
        name="GitHub App Token",
        pattern=r'(ghu|ghs)_[A-Za-z0-9_]{36,}',
        severity="critical",
        description="GitHub App Token"
    ),
]

# Generic Passwords and Secrets
GENERIC_SECRET_PATTERNS = [
    SecretPattern(
        name="Password in Code",
        pattern=r'["\']?password["\']?\s*[=:]\s*["\']([^"\']{8,})["\']',
        severity="high",
        description="Hardcoded Password"
    ),
    SecretPattern(
        name="Secret Key",
        pattern=r'["\']?secret[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
        severity="high",
        description="Secret Key"
    ),
    SecretPattern(
        name="Database Connection String",
        pattern=r'(mongodb|mysql|postgres|postgresql)://[^:]+:[^@]+@[^/]+',
        severity="critical",
        description="Database Connection String with Credentials"
    ),
    SecretPattern(
        name="JDBC Connection String",
        pattern=r'jdbc:[^\s]+password=[^\s&]+',
        severity="critical",
        description="JDBC Connection String with Password"
    ),
]

# Base64 Encoded Secrets
BASE64_PATTERNS = [
    SecretPattern(
        name="Base64 Encoded Secret",
        pattern=r'["\']?secret["\']?\s*[=:]\s*["\']([A-Za-z0-9+/]{40,}={0,2})["\']',
        severity="medium",
        description="Potentially Base64 Encoded Secret"
    ),
    SecretPattern(
        name="Base64 API Key",
        pattern=r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9+/]{40,}={0,2})["\']',
        severity="medium",
        description="Potentially Base64 Encoded API Key"
    ),
]

# Social Media / Communications
SOCIAL_PATTERNS = [
    SecretPattern(
        name="Twitter API Key",
        pattern=r'twitter[_-]?api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9]{25,})["\']',
        severity="high",
        description="Twitter API Key"
    ),
    SecretPattern(
        name="Twitter Bearer Token",
        pattern=r'AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{50,}',
        severity="high",
        description="Twitter Bearer Token"
    ),
    SecretPattern(
        name="Facebook Access Token",
        pattern=r'EAACEdEose0cBA[0-9A-Za-z]+',
        severity="high",
        description="Facebook Access Token"
    ),
    SecretPattern(
        name="Mailgun API Key",
        pattern=r'key-[0-9a-zA-Z]{32}',
        severity="high",
        description="Mailgun API Key"
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        severity="critical",
        description="SendGrid API Key"
    ),
]

# Cloud Providers
CLOUD_PATTERNS = [
    SecretPattern(
        name="Azure Storage Key",
        pattern=r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
        severity="critical",
        description="Azure Storage Account Key"
    ),
    SecretPattern(
        name="Heroku API Key",
        pattern=r'[hH][eE][rR][oO][kK][uU].*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
        severity="critical",
        description="Heroku API Key"
    ),
    SecretPattern(
        name="DigitalOcean Token",
        pattern=r'dop_v1_[a-f0-9]{64}',
        severity="critical",
        description="DigitalOcean Personal Access Token"
    ),
]

# All patterns combined
ALL_SECRET_PATTERNS = (
    AWS_PATTERNS +
    PRIVATE_KEY_PATTERNS +
    JWT_PATTERNS +
    API_KEY_PATTERNS +
    GOOGLE_PATTERNS +
    GITHUB_PATTERNS +
    GENERIC_SECRET_PATTERNS +
    BASE64_PATTERNS +
    SOCIAL_PATTERNS +
    CLOUD_PATTERNS
)


class SecretDetector:
    """
    Secret detector using pattern matching
    """
    
    def __init__(self, patterns: List[SecretPattern] = None):
        """
        Initialize detector with patterns
        
        Args:
            patterns: List of SecretPattern objects (defaults to ALL_SECRET_PATTERNS)
        """
        self.patterns = patterns or ALL_SECRET_PATTERNS
    
    def scan(self, content: str, context_chars: int = 100) -> List[Dict]:
        """
        Scan content for secrets
        
        Args:
            content: Content to scan
            context_chars: Number of characters to include in context
            
        Returns:
            List of detected secrets with metadata
        """
        findings = []
        
        for pattern in self.patterns:
            matches = pattern.regex.finditer(content)
            
            for match in matches:
                start = max(0, match.start() - context_chars)
                end = min(len(content), match.end() + context_chars)
                context = content[start:end]
                
                finding = {
                    "type": pattern.name,
                    "value": match.group(0),
                    "context": context,
                    "severity": pattern.severity,
                    "description": pattern.description,
                    "position": match.start(),
                }
                
                findings.append(finding)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a file for secrets
        
        Args:
            file_path: Path to file
            
        Returns:
            List of detected secrets
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = self.scan(content)
            
            # Add file path to findings
            for finding in findings:
                finding['file'] = file_path
            
            return findings
        except Exception as e:
            return []
    
    def get_patterns_by_severity(self, severity: str) -> List[SecretPattern]:
        """
        Get patterns filtered by severity
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            List of matching patterns
        """
        return [p for p in self.patterns if p.severity == severity]
    
    def get_critical_patterns(self) -> List[SecretPattern]:
        """Get only critical severity patterns"""
        return self.get_patterns_by_severity("critical")
