#!/usr/bin/env python3
"""
Scope Validator for Bug Bounty Programs
Validates targets against program scope definitions from CSV files
"""

import csv
import re
import fnmatch
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .config import AmazonConfig, ShopifyConfig, get_amazon_config, get_shopify_config


@dataclass
class ScopeEntry:
    """Represents a single scope entry from CSV"""
    identifier: str
    asset_type: str
    instruction: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    max_severity: str
    environment: str = ""  # Core, Non-core, etc.


class ScopeValidator:
    """Base class for scope validation"""

    def __init__(self):
        self.scope_entries: List[ScopeEntry] = []
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []

    def load_from_csv(self, csv_path: Path) -> None:
        """Load scope entries from CSV file"""
        if not csv_path.exists():
            raise FileNotFoundError(f"Scope file not found: {csv_path}")

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                eligible_bounty = row.get('eligible_for_bounty', '').lower() == 'true'
                eligible_submit = row.get('eligible_for_submission', '').lower() == 'true'

                instruction = row.get('instruction', '')
                environment = ""
                if "Environment: Core" in instruction:
                    environment = "Core"
                elif "Environment: Non-core" in instruction:
                    environment = "Non-core"

                entry = ScopeEntry(
                    identifier=row.get('identifier', ''),
                    asset_type=row.get('asset_type', ''),
                    instruction=instruction,
                    eligible_for_bounty=eligible_bounty,
                    eligible_for_submission=eligible_submit,
                    max_severity=row.get('max_severity', ''),
                    environment=environment,
                )
                self.scope_entries.append(entry)

                if eligible_bounty or eligible_submit:
                    self.in_scope.append(entry.identifier)
                else:
                    self.out_of_scope.append(entry.identifier)

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is in scope. Returns (is_in_scope, reason)"""
        raise NotImplementedError

    def get_bounty_eligible(self) -> List[ScopeEntry]:
        """Get all bounty-eligible entries"""
        return [e for e in self.scope_entries if e.eligible_for_bounty]

    def get_core_assets(self) -> List[ScopeEntry]:
        """Get core environment assets"""
        return [e for e in self.scope_entries if e.environment == "Core"]


class AmazonScopeValidator(ScopeValidator):
    """Scope validator for Amazon VRP"""

    def __init__(self, config: Optional[AmazonConfig] = None):
        super().__init__()
        self.config = config or get_amazon_config()
        self.load_from_csv(self.config.scope_file)

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Check if target is in scope for Amazon VRP
        Returns (is_in_scope, reason)
        """
        # Extract domain from URL if needed
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target

        domain_lower = domain.lower()

        # Check out-of-scope patterns first (these are HARD exclusions)
        for pattern in self.config.out_of_scope_patterns:
            if pattern.lower() in domain_lower:
                return False, f"Contains out-of-scope pattern: {pattern}"

        # Check for AWS (special case - always out of scope)
        if 'aws' in domain_lower:
            return False, "AWS assets are strictly out of scope"

        # Check for .a2z domains
        if '.a2z' in domain_lower or domain_lower.endswith('.a2z'):
            return False, ".a2z domains are out of scope"

        # Check for .dev domains
        if '.dev' in domain_lower or domain_lower.endswith('.dev'):
            return False, ".dev domains are out of scope"

        # Check against wildcard patterns
        for wildcard in self.config.in_scope_wildcards:
            # Convert wildcard to regex pattern
            if wildcard.startswith('*.'):
                base_domain = wildcard[2:]  # Remove *.
                if domain_lower.endswith(base_domain) or domain_lower == base_domain:
                    return True, f"Matches in-scope wildcard: {wildcard}"
            elif domain_lower == wildcard.lower():
                return True, f"Exact match: {wildcard}"

        # Check explicit scope entries
        for entry in self.scope_entries:
            identifier = entry.identifier.lower()

            # Handle wildcard identifiers
            if identifier.startswith('*.'):
                base = identifier[2:]
                if domain_lower.endswith(base):
                    if entry.eligible_for_bounty or entry.eligible_for_submission:
                        return True, f"Matches scope entry: {entry.identifier}"
                    else:
                        return False, f"Matches out-of-scope entry: {entry.identifier}"

            # Handle URL patterns
            elif '*' in identifier:
                pattern = identifier.replace('.', r'\.').replace('*', '.*')
                if re.match(pattern, domain_lower):
                    if entry.eligible_for_bounty or entry.eligible_for_submission:
                        return True, f"Matches scope pattern: {entry.identifier}"

            # Exact match
            elif domain_lower == identifier or domain_lower in identifier:
                if entry.eligible_for_bounty or entry.eligible_for_submission:
                    return True, f"Exact scope match: {entry.identifier}"

        # Check if it's an Amazon domain at all
        if 'amazon' in domain_lower:
            # It's an Amazon domain but not explicitly listed
            return True, "Amazon domain - verify against full scope"

        return False, "Target not found in scope"

    def filter_targets(self, targets: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Filter a list of targets, returning (in_scope, out_of_scope_with_reasons)
        """
        in_scope = []
        out_of_scope = []

        for target in targets:
            is_valid, reason = self.is_in_scope(target)
            if is_valid:
                in_scope.append(target)
            else:
                out_of_scope.append((target, reason))

        return in_scope, out_of_scope


class ShopifyScopeValidator(ScopeValidator):
    """Scope validator for Shopify Bug Bounty"""

    def __init__(self, config: Optional[ShopifyConfig] = None):
        super().__init__()
        self.config = config or get_shopify_config()
        self.load_from_csv(self.config.scope_file)

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Check if target is in scope for Shopify
        Returns (is_in_scope, reason)
        """
        # Extract domain from URL if needed
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target

        domain_lower = domain.lower()

        # Check explicit out-of-scope first
        for oos in self.config.out_of_scope:
            if oos.startswith('*.'):
                base = oos[2:]
                if domain_lower.endswith(base) and domain_lower != base:
                    # Check if it's a more specific subdomain
                    if fnmatch.fnmatch(domain_lower, oos):
                        return False, f"Matches out-of-scope: {oos}"
            elif domain_lower == oos.lower():
                return False, f"Explicitly out of scope: {oos}"

        # Check specific out-of-scope domains from CSV
        for entry in self.scope_entries:
            if not entry.eligible_for_bounty and not entry.eligible_for_submission:
                if domain_lower == entry.identifier.lower():
                    return False, f"Out of scope per program: {entry.instruction[:100]}"

        # Check core assets first (higher priority)
        for core in self.config.core_assets:
            if core.startswith('*.'):
                base = core[2:]
                if domain_lower.endswith(base):
                    return True, f"Core asset: {core} (eligible for bounty)"
            elif domain_lower == core.lower():
                return True, f"Core asset: {core} (eligible for bounty)"

        # Check non-core assets
        for non_core in self.config.non_core_assets:
            if non_core.startswith('*.'):
                base = non_core[2:]
                if domain_lower.endswith(base):
                    return True, f"Non-core asset: {non_core} (case-by-case bounty)"
            elif domain_lower == non_core.lower():
                return True, f"Non-core asset: {non_core} (case-by-case bounty)"

        # Check scope entries
        for entry in self.scope_entries:
            identifier = entry.identifier.lower()

            if identifier.startswith('*.'):
                base = identifier[2:]
                if domain_lower.endswith(base):
                    if entry.eligible_for_bounty:
                        return True, f"Scope match: {entry.identifier} ({entry.environment})"
                    elif entry.eligible_for_submission:
                        return True, f"Submission eligible: {entry.identifier}"

            elif domain_lower == identifier:
                if entry.eligible_for_bounty:
                    return True, f"Exact match: {entry.identifier} ({entry.environment})"
                elif entry.eligible_for_submission:
                    return True, f"Submission eligible: {entry.identifier}"

        # Check if it's a Shopify domain at all
        if 'shopify' in domain_lower or 'myshopify' in domain_lower:
            return True, "Shopify domain - verify against full scope"

        return False, "Target not found in scope"

    def filter_targets(self, targets: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Filter a list of targets, returning (in_scope, out_of_scope_with_reasons)
        """
        in_scope = []
        out_of_scope = []

        for target in targets:
            is_valid, reason = self.is_in_scope(target)
            if is_valid:
                in_scope.append(target)
            else:
                out_of_scope.append((target, reason))

        return in_scope, out_of_scope


def validate_target(target: str, program: str = "amazon") -> Tuple[bool, str]:
    """
    Quick validation function for a single target
    program: 'amazon' or 'shopify'
    """
    if program.lower() == "amazon":
        validator = AmazonScopeValidator()
    elif program.lower() == "shopify":
        validator = ShopifyScopeValidator()
    else:
        return False, f"Unknown program: {program}"

    return validator.is_in_scope(target)


if __name__ == "__main__":
    import sys

    # Demo usage
    print("=" * 60)
    print("AMAZON VRP SCOPE VALIDATOR")
    print("=" * 60)

    amazon_validator = AmazonScopeValidator()
    test_amazon = [
        "www.amazon.com",
        "api.amazon.com",
        "aws.amazon.com",  # Should be OUT of scope
        "s3.amazonaws.com",  # Should be OUT of scope
        "test.amazon.com",  # Should be OUT of scope (test environment)
        "something.a2z.com",  # Should be OUT of scope
        "primevideo.com",
        "amazon.de",
    ]

    print("\nTesting Amazon targets:")
    for target in test_amazon:
        is_valid, reason = amazon_validator.is_in_scope(target)
        status = "IN SCOPE" if is_valid else "OUT OF SCOPE"
        print(f"  {target}: {status} - {reason}")

    print("\n" + "=" * 60)
    print("SHOPIFY SCOPE VALIDATOR")
    print("=" * 60)

    shopify_validator = ShopifyScopeValidator()
    test_shopify = [
        "admin.shopify.com",  # Core - in scope
        "partners.shopify.com",  # Core - in scope
        "community.shopify.com",  # Out of scope (third party)
        "test-store.myshopify.com",  # In scope (your store)
        "shop.app",  # Core - in scope
        "investors.shopify.com",  # Out of scope
        "random.shopify.io",  # Non-core
    ]

    print("\nTesting Shopify targets:")
    for target in test_shopify:
        is_valid, reason = shopify_validator.is_in_scope(target)
        status = "IN SCOPE" if is_valid else "OUT OF SCOPE"
        print(f"  {target}: {status} - {reason}")

    print("\n" + "=" * 60)
    print("BOUNTY-ELIGIBLE ASSETS")
    print("=" * 60)

    print("\nAmazon bounty-eligible wildcards:")
    for entry in amazon_validator.get_bounty_eligible()[:10]:
        if entry.asset_type == "WILDCARD":
            print(f"  - {entry.identifier}")

    print("\nShopify core assets:")
    for entry in shopify_validator.get_core_assets():
        print(f"  - {entry.identifier} ({entry.environment})")
