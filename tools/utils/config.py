#!/usr/bin/env python3
"""
Bug Bounty Scanner Configuration
Configuration for Amazon VRP and Shopify Bug Bounty Programs
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
AMAZON_DIR = BASE_DIR / "Amazon"
SHOPIFY_DIR = BASE_DIR / "Shopify"

@dataclass
class AmazonConfig:
    """Amazon VRP Configuration - MUST follow program rules"""

    # REQUIRED: User-Agent string (replace 'yourh1username' with actual username)
    h1_username: str = "yourh1username"

    @property
    def user_agent(self) -> str:
        return f"amazonvrpresearcher_{self.h1_username}"

    # Rate limiting: MAX 5 requests per second
    rate_limit: float = 5.0  # requests per second
    request_delay: float = 0.2  # seconds between requests (1/5 = 0.2)

    # Scope file
    scope_file: Path = field(default_factory=lambda: AMAZON_DIR / "scopes_for_amazonvrp_at_2026-01-05_16_04_00_UTC.csv")

    # Out-of-scope patterns (from program rules)
    out_of_scope_patterns: List[str] = field(default_factory=lambda: [
        "aws",           # Anything containing aws
        ".a2z.",         # .a2z domains
        ".a2z",          # ending with .a2z
        ".dev",          # .dev domains
        "test",          # test environments
        "qa",            # qa environments
        "integ",         # integration environments
        "preprod",       # pre-production
        "gamma",         # gamma environments
        "beta",          # beta environments
        "staging",       # staging environments
        "user-aliases",  # user alias domains
    ])

    # In-scope wildcard patterns
    in_scope_wildcards: List[str] = field(default_factory=lambda: [
        "*.amazon.com",
        "*.amazon.co.uk",
        "*.amazon.de",
        "*.amazon.fr",
        "*.amazon.it",
        "*.amazon.es",
        "*.amazon.ca",
        "*.amazon.co.jp",
        "*.amazon.in",
        "*.amazon.com.au",
        "*.amazon.com.br",
        "*.amazon.com.mx",
        "*.amazon.nl",
        "*.amazon.pl",
        "*.amazon.se",
        "*.amazon.ae",
        "*.amazon.sg",
        "*.amazon.eg",
        "*.amazon.sa",
        "*.amazon.com.tr",
        "*.amazon.com.be",
        "*.amazon.cl",
        "*.amazon.cn",
        "*.amazon.com.co",
        "*.amazon.com.ng",
        "*.amazon.co.za",
        "primevideo.com",
        "amazonpayinsurance.in",
    ])

    # Timeout settings
    request_timeout: int = 30

    # Output directory
    output_dir: Path = field(default_factory=lambda: AMAZON_DIR / "scan_results")

    # Email format for account creation
    @property
    def test_email(self) -> str:
        return f"{self.h1_username}@wearehackerone.com"


@dataclass
class ShopifyConfig:
    """Shopify Bug Bounty Configuration - MUST follow program rules"""

    # HackerOne username for email
    h1_username: str = "yourh1username"

    # User-Agent (no specific requirement, but be respectful)
    user_agent: str = "ShopifyBugBountyResearcher"

    # Rate limiting (be respectful, follow API guidelines)
    rate_limit: float = 10.0  # requests per second
    request_delay: float = 0.1  # seconds between requests

    # Scope file
    scope_file: Path = field(default_factory=lambda: SHOPIFY_DIR / "scopes_for_shopify_at_2026-01-05_16_03_25_UTC.csv")

    # Core assets (eligible for bounty, critical severity)
    core_assets: List[str] = field(default_factory=lambda: [
        "your-store.myshopify.com",  # Your development stores
        "accounts.shopify.com",
        "admin.shopify.com",
        "partners.shopify.com",
        "shopify.plus",
        "arrive-server.shopifycloud.com",
        "shop.app",
        "*.pci.shopifyinc.com",
    ])

    # Non-core assets (lower bounty, case-by-case)
    non_core_assets: List[str] = field(default_factory=lambda: [
        "*.shopify.com",
        "*.shopifycloud.com",
        "*.shopifykloud.com",
        "*.shopify.io",
        "*.shopifycs.com",
        "linkpop.com",
        "shopifyinbox.com",
    ])

    # Out of scope (do NOT test)
    out_of_scope: List[str] = field(default_factory=lambda: [
        "community.shopify.com",
        "community.shopify.dev",
        "investors.shopify.com",
        "academy.shopify.com",
        "livechat.shopify.com",
        "cdn.shopify.com",
        "*.email.shopify.com",
        "supplier-portal.shopifycloud.com",
    ])

    # Timeout settings
    request_timeout: int = 30

    # Output directory
    output_dir: Path = field(default_factory=lambda: SHOPIFY_DIR / "scan_results")

    # Partner signup URL
    partner_signup_url: str = "https://partners.shopify.com/signup/bugbounty"

    # Email format for account creation
    @property
    def test_email(self) -> str:
        return f"{self.h1_username}@wearehackerone.com"


# Vulnerability priorities (for both programs)
VULN_PRIORITIES = {
    "critical": [
        "RCE",              # Remote Code Execution
        "SQLi",             # SQL Injection
        "XXE",              # XML External Entity
        "XSS_high_impact",  # High-impact XSS
        "Auth_bypass",      # Authentication Bypass
    ],
    "high": [
        "SSRF",             # Server-Side Request Forgery
        "IDOR",             # Insecure Direct Object Reference
        "Priv_escalation",  # Privilege Escalation
        "Auth_bypass",      # Authorization Bypass
    ],
    "medium": [
        "Directory_traversal",
        "CORS",
        "CRLF",
        "CSRF",
        "Open_redirect",
        "Request_smuggling",
    ],
    "low": [
        "Information_disclosure",
        "Missing_headers",  # Generally not eligible
    ]
}

# Common test payloads (safe, non-destructive)
TEST_PAYLOADS = {
    "xss_reflection": [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ],
    "sqli_detection": [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1 UNION SELECT NULL--",
    ],
    "ssrf_detection": [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata
    ],
    "path_traversal": [
        "../",
        "..\\",
        "....//",
        "%2e%2e%2f",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
    ],
}

# HTTP headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Referrer-Policy",
]

def get_amazon_config(h1_username: Optional[str] = None) -> AmazonConfig:
    """Get Amazon configuration with optional username override"""
    config = AmazonConfig()
    if h1_username:
        config.h1_username = h1_username
    return config

def get_shopify_config(h1_username: Optional[str] = None) -> ShopifyConfig:
    """Get Shopify configuration with optional username override"""
    config = ShopifyConfig()
    if h1_username:
        config.h1_username = h1_username
    return config
