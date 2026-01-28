#!/usr/bin/env python3
"""
Quick test to verify Anduril configuration is working
"""

import sys
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent / "tools"))

from utils.config import get_anduril_config

# Test the configuration
config = get_anduril_config("test_user")

print("=== Anduril Industries Configuration Test ===\n")
print(f"✓ User-Agent: {config.user_agent}")
print(f"✓ Custom Headers: {config.custom_headers}")
print(f"✓ Rate Limit: {config.rate_limit} req/sec")
print(f"✓ Request Delay: {config.request_delay}s")
print(f"✓ Timeout: {config.request_timeout}s")
print(f"✓ Test Email: {config.test_email}")
print(f"\n✓ Scope File: {config.scope_file}")
print(f"✓ Output Directory: {config.output_dir}")

print(f"\n✓ In-Scope Wildcards ({len(config.in_scope_wildcards)}):")
for domain in config.in_scope_wildcards:
    print(f"  - {domain}")

print(f"\n✓ Out-of-Scope ({len(config.out_of_scope)}):")
for domain in config.out_of_scope:
    print(f"  - {domain}")

print(f"\n✓ Out-of-Scope Patterns ({len(config.out_of_scope_patterns)}):")
for pattern in config.out_of_scope_patterns:
    print(f"  - {pattern}")

print("\n" + "=" * 50)
print("Configuration loaded successfully!")
print("=" * 50)
print(config.program_notes)
