"""
Bug Bounty Scanning Tools
For Amazon VRP and Shopify Bug Bounty programs
"""

from .config import (
    AmazonConfig,
    ShopifyConfig,
    get_amazon_config,
    get_shopify_config,
)
from .scope_validator import (
    AmazonScopeValidator,
    ShopifyScopeValidator,
    validate_target,
)
from .scanner import (
    AmazonScanner,
    ShopifyScanner,
    Finding,
    ScanResult,
)

__version__ = "1.0.0"
__all__ = [
    "AmazonConfig",
    "ShopifyConfig",
    "get_amazon_config",
    "get_shopify_config",
    "AmazonScopeValidator",
    "ShopifyScopeValidator",
    "validate_target",
    "AmazonScanner",
    "ShopifyScanner",
    "Finding",
    "ScanResult",
]
