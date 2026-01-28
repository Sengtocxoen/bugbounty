"""
Verification Module - Base Framework
====================================

Base classes and utilities for vulnerability verification.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for verified vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(Enum):
    """Confidence level for verification"""
    CONFIRMED = "confirmed"  # 100% confirmed exploitable
    HIGH = "high"  # Very likely exploitable (90%+)
    MEDIUM = "medium"  # Possibly exploitable (50-90%)
    LOW = "low"  # Unlikely exploitable (<50%)
    UNVERIFIED = "unverified"  # Could not verify


@dataclass
class VerificationResult:
    """Result from vulnerability verification"""
    verified: bool
    confidence: ConfidenceLevel
    severity: Severity
    finding_type: str  # e.g., "exposed_service", "git_leak", "admin_panel"
    target: str
    details: str
    proof: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "verified": self.verified,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "finding_type": self.finding_type,
            "target": self.target,
            "details": self.details,
            "proof": self.proof,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
        }


class BaseVerifier(ABC):
    """Base class for all verifiers"""
    
    def __init__(self, user_agent: Optional[str] = None, timeout: int = 10):
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.timeout = timeout
        self.results: List[VerificationResult] = []
    
    @abstractmethod
    def verify(self, *args, **kwargs) -> VerificationResult:
        """Verify a specific vulnerability. Must be implemented by subclasses."""
        pass
    
    def get_headers(self, additional_headers: Optional[Dict] = None) -> Dict[str, str]:
        """Get default headers with user-agent"""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        }
        if additional_headers:
            headers.update(additional_headers)
        return headers
