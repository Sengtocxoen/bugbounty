#!/usr/bin/env python3
"""
Bug Bounty Program Configuration Module
========================================
Ensures compliance with bug bounty program requirements including:
- User-Agent strings
- Rate limiting
- Scope validation
- Account creation requirements

Supported Programs:
- Amazon VRP
- Shopify Bug Bounty
- Generic configuration
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Pattern
from urllib.parse import urlparse


@dataclass
class BugBountyConfig:
    """Configuration for a bug bounty program"""
    name: str
    user_agent_template: str
    rate_limit: float  # requests per second
    email_format: str
    scope_patterns: List[str] = field(default_factory=list)
    out_of_scope_patterns: List[str] = field(default_factory=list)
    special_rules: Dict[str, str] = field(default_factory=dict)

    def get_user_agent(self, username: str) -> str:
        """Generate the required user agent string"""
        return self.user_agent_template.format(username=username)

    def get_email(self, username: str) -> str:
        """Generate the required email address"""
        return self.email_format.format(username=username)

    def is_in_scope(self, domain: str) -> bool:
        """Check if domain is in scope"""
        if not self.scope_patterns:
            return True  # No scope defined = assume in scope

        for pattern in self.scope_patterns:
            if re.match(pattern.replace('*', '.*'), domain, re.IGNORECASE):
                return True
        return False

    def is_out_of_scope(self, domain: str) -> bool:
        """Check if domain is explicitly out of scope"""
        for pattern in self.out_of_scope_patterns:
            if re.match(pattern.replace('*', '.*'), domain, re.IGNORECASE):
                return True
        return False

    def validate_target(self, domain: str) -> Dict:
        """Validate a target domain"""
        result = {
            "domain": domain,
            "in_scope": False,
            "out_of_scope": False,
            "reason": "",
            "allowed": False
        }

        if self.is_out_of_scope(domain):
            result["out_of_scope"] = True
            result["reason"] = "Domain matches out-of-scope pattern"
            result["allowed"] = False
        elif self.is_in_scope(domain):
            result["in_scope"] = True
            result["allowed"] = True
        else:
            result["reason"] = "Domain not in defined scope"
            result["allowed"] = False

        return result


# Amazon VRP Configuration
AMAZON_VRP = BugBountyConfig(
    name="Amazon VRP",
    user_agent_template="amazonvrpresearcher_{username}",
    rate_limit=5.0,  # Max 5 requests per second
    email_format="{username}@wearehackerone.com",
    scope_patterns=[
        r".*\.amazon\..*",  # All retail marketplaces
        r".*\.amazon$",
    ],
    out_of_scope_patterns=[
        r".*aws.*",  # Anything with aws
        r".*\.a2z$",  # .a2z domains
        r".*\.dev$",  # .dev domains
        r".*test.*",  # test environments
        r".*qa.*",  # qa environments
        r".*integ.*",  # integration
        r".*preprod.*",  # pre-production
        r".*gamma.*",  # gamma
        r".*beta.*",  # beta
    ],
    special_rules={
        "third_party": "Do NOT use 3rd party sites for testing (e.g., XSS Hunter) - must use self-hosted infrastructure",
        "subdomain_takeover": "For subdomain takeovers: serve HTML file on hidden path with H1 username in HTML comment",
        "genai_testing": "Include: Timestamp, IP, Prompt String, Security Impact. Prompt response content without security impact is OUT OF SCOPE",
    }
)

# Shopify Bug Bounty Configuration
SHOPIFY_BB = BugBountyConfig(
    name="Shopify Bug Bounty",
    user_agent_template="ShopifyBugBounty_{username}",
    rate_limit=10.0,  # Default reasonable rate
    email_format="{username}@wearehackerone.com",
    scope_patterns=[
        r".*\.shopify\.com",
        r".*\.myshopify\.com",
    ],
    out_of_scope_patterns=[
        # Only test stores you created
    ],
    special_rules={
        "account_creation": "Register via: https://partners.shopify.com/signup/bugbounty",
        "testing_restriction": "Test ONLY against stores you created. Testing against live merchants is PROHIBITED",
        "no_support_contact": "Do NOT contact Shopify Support about testing, program questions, or report updates - will result in disqualification and potential ban",
    }
)

# Generic Bug Bounty Configuration
GENERIC_BB = BugBountyConfig(
    name="Generic Bug Bounty",
    user_agent_template="SecurityResearcher_{username}",
    rate_limit=5.0,
    email_format="{username}@wearehackerone.com",
    scope_patterns=[],  # No restrictions
    out_of_scope_patterns=[],
    special_rules={
        "general": "Always verify scope before testing. Follow responsible disclosure.",
    }
)


# Program registry
PROGRAMS = {
    "amazon": AMAZON_VRP,
    "shopify": SHOPIFY_BB,
    "generic": GENERIC_BB,
}


def get_program_config(program_name: str) -> BugBountyConfig:
    """Get configuration for a specific program"""
    return PROGRAMS.get(program_name.lower(), GENERIC_BB)


def detect_program(domain: str) -> Optional[BugBountyConfig]:
    """Attempt to detect the bug bounty program based on domain"""
    domain_lower = domain.lower()

    if 'amazon' in domain_lower:
        return AMAZON_VRP
    elif 'shopify' in domain_lower or 'myshopify' in domain_lower:
        return SHOPIFY_BB

    return GENERIC_BB


def validate_targets(domains: List[str], program: BugBountyConfig) -> Dict:
    """Validate a list of domains against program scope"""
    results = {
        "allowed": [],
        "denied": [],
        "warnings": []
    }

    for domain in domains:
        validation = program.validate_target(domain)

        if validation["allowed"]:
            results["allowed"].append(domain)
        else:
            results["denied"].append({
                "domain": domain,
                "reason": validation["reason"]
            })

    return results


def print_program_rules(program: BugBountyConfig):
    """Print important rules for a program"""
    print(f"\n{'='*60}")
    print(f"Bug Bounty Program: {program.name}")
    print(f"{'='*60}")
    print(f"Rate Limit: {program.rate_limit} requests/second")
    print(f"Email Format: {program.email_format}")
    print(f"User-Agent: {program.user_agent_template}")
    print()

    if program.special_rules:
        print("Special Rules:")
        for rule_name, rule_text in program.special_rules.items():
            print(f"  - {rule_name}: {rule_text}")

    if program.out_of_scope_patterns:
        print("\nOut of Scope Patterns:")
        for pattern in program.out_of_scope_patterns[:5]:
            print(f"  - {pattern}")

    print(f"{'='*60}\n")


class ScopeValidator:
    """Validate targets against bug bounty scope"""

    def __init__(self, program: BugBountyConfig):
        self.program = program
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        self.scope_regexes = [
            re.compile(p.replace('*', '.*'), re.IGNORECASE)
            for p in self.program.scope_patterns
        ]
        self.oos_regexes = [
            re.compile(p.replace('*', '.*'), re.IGNORECASE)
            for p in self.program.out_of_scope_patterns
        ]

    def is_valid(self, domain: str) -> bool:
        """Check if domain is valid for testing"""
        # First check out of scope
        for regex in self.oos_regexes:
            if regex.match(domain):
                return False

        # Then check in scope (if patterns defined)
        if self.scope_regexes:
            for regex in self.scope_regexes:
                if regex.match(domain):
                    return True
            return False

        return True  # No scope defined = allow

    def filter_domains(self, domains: List[str]) -> List[str]:
        """Filter list to only valid domains"""
        return [d for d in domains if self.is_valid(d)]

    def get_warnings(self, domain: str) -> List[str]:
        """Get any warnings for a domain"""
        warnings = []

        # Check for test/staging indicators
        test_indicators = ['test', 'staging', 'dev', 'qa', 'uat', 'sandbox']
        for indicator in test_indicators:
            if indicator in domain.lower():
                warnings.append(f"Domain contains '{indicator}' - verify it's in scope")

        return warnings
