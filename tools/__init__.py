"""
Bug Bounty Scanning & Discovery Tools
For Amazon VRP and Shopify Bug Bounty programs

Modules:
- config: Configuration for each program
- scope_validator: Validate targets against program scope
- scanner: Basic vulnerability scanning
- subdomain_discovery: Find subdomains via CT logs and DNS
- endpoint_discovery: Find endpoints, paths, and APIs
- tech_detection: Detect technologies and frameworks
- js_analyzer: Analyze JavaScript for secrets and sinks
- param_fuzzer: Fuzz parameters for vulnerabilities
- bug_discovery: Main orchestrator for full discovery pipeline
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
from .subdomain_discovery import (
    SubdomainDiscovery,
    AmazonSubdomainDiscovery,
    ShopifySubdomainDiscovery,
)
from .endpoint_discovery import (
    EndpointDiscovery,
    AmazonEndpointDiscovery,
    ShopifyEndpointDiscovery,
)
from .tech_detection import (
    TechDetector,
    AmazonTechDetector,
    ShopifyTechDetector,
)
from .js_analyzer import (
    JSAnalyzer,
    AmazonJSAnalyzer,
    ShopifyJSAnalyzer,
)
from .param_fuzzer import (
    ParamFuzzer,
    AmazonParamFuzzer,
    ShopifyParamFuzzer,
)

__version__ = "1.1.0"
__all__ = [
    # Config
    "AmazonConfig",
    "ShopifyConfig",
    "get_amazon_config",
    "get_shopify_config",
    # Scope Validation
    "AmazonScopeValidator",
    "ShopifyScopeValidator",
    "validate_target",
    # Scanning
    "AmazonScanner",
    "ShopifyScanner",
    "Finding",
    "ScanResult",
    # Discovery
    "SubdomainDiscovery",
    "AmazonSubdomainDiscovery",
    "ShopifySubdomainDiscovery",
    "EndpointDiscovery",
    "AmazonEndpointDiscovery",
    "ShopifyEndpointDiscovery",
    "TechDetector",
    "AmazonTechDetector",
    "ShopifyTechDetector",
    "JSAnalyzer",
    "AmazonJSAnalyzer",
    "ShopifyJSAnalyzer",
    "ParamFuzzer",
    "AmazonParamFuzzer",
    "ShopifyParamFuzzer",
]
