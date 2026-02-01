#!/usr/bin/env python3
"""
WAF Evasion Module
Detects Web Application Firewalls and applies evasion techniques.
- Fingerprinting: Cloudflare, AWS WAF, Akamai, etc.
- Evasion: Header randomization, payload encoding, adaptive delays.
"""

import re
import time
import random
import base64
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from utils.config import get_amazon_config, get_shopify_config

@dataclass
class WAFInfo:
    """Information about detected WAF"""
    name: str
    detected: bool = False
    confidence: str = "low"
    bypass_techniques: List[str] = field(default_factory=list)

class WAFEvader:
    """Handles WAF detection and evasion"""

    def __init__(self, rate_limit: float = 5.0, user_agent_prefix: str = "BugBounty"):
        self.rate_limit = rate_limit
        self.user_agent_prefix = user_agent_prefix
        self.last_status_code = 200
        self.consecutive_blocks = 0
        self.current_delay = 1.0 / rate_limit
        
        # WAF Signatures (Headers, Cookies, Content)
        self.signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
                "cookies": ["__cfduid", "cf_clearance"],
                "content": ["attention required! | cloudflare", "cloudflare ray id"]
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amz-apigw-id"],
                "content": ["403 forbidden", "request blocked"]
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop"],
                "content": ["access denied", "akamai global host"]
            },
            "ModSecurity": {
                "content": ["mod_security", "not acceptable"]
            },
            "Incapsula": {
                "headers": ["x-cdn", "incap-ses"],
                "cookies": ["visid_incap", "incap_ses"]
            }
        }
        
        # User Agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
        ]

    def detect_waf(self, url: str, response: Optional[requests.Response] = None) -> WAFInfo:
        """Detect WAF presence and type"""
        waf_info = WAFInfo(name="Unknown")
        
        if not response:
            try:
                response = requests.get(url, timeout=10, headers={'User-Agent': self.random_user_agent()})
            except:
                return waf_info

        # Check headers
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = response.cookies.keys()
        content = response.text.lower()
        
        for name, sig in self.signatures.items():
            score = 0
            
            # Check headers
            if "headers" in sig:
                for h in sig["headers"]:
                    if h in headers:
                        score += 1
            
            # Check cookies
            if "cookies" in sig:
                for c in sig["cookies"]:
                    for cookie in cookies:
                        if c in cookie:
                            score += 1
            
            # Check content (only if error/block)
            if response.status_code in [403, 406, 429, 503]:
                if "content" in sig:
                    for s in sig["content"]:
                        if s in content:
                            score += 2
            
            if score > 0:
                waf_info.name = name
                waf_info.detected = True
                waf_info.confidence = "high" if score > 1 else "medium"
                
                # Suggest bypasses
                if name == "Cloudflare":
                    waf_info.bypass_techniques = ["ip_rotation", "slow_rate"]
                elif name == "ModSecurity":
                    waf_info.bypass_techniques = ["case_variation", "encoding"]
                
                return waf_info
                
        return waf_info

    def random_user_agent(self) -> str:
        """Return a random user agent"""
        return random.choice(self.user_agents)

    def generate_headers(self, base_headers: Dict = None) -> Dict:
        """Generate randomized headers for evasion"""
        headers = base_headers.copy() if base_headers else {}
        
        # Rotate UA
        headers['User-Agent'] = self.random_user_agent()
        
        # Spoof IP headers
        spoof_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers['X-Forwarded-For'] = spoof_ip
        headers['X-Real-IP'] = spoof_ip
        headers['X-Originating-IP'] = spoof_ip
        headers['Client-IP'] = spoof_ip
        
        return headers

    def encode_payload(self, payload: str, method: str = "url") -> str:
        """Encode payload to bypass filters"""
        if method == "url":
            return urllib.parse.quote(payload)
        elif method == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "unicode":
            # Simple unicode escape
            return "".join([f"\\u{ord(c):04x}" for c in payload])
        elif method == "html":
            return "".join([f"&#x{ord(c):x};" for c in payload])
        elif method == "comment":
             # Inject comments in SQL/script
             # e.g., UN/**/ION
             return payload.replace(" ", "/**/").replace("SELECT", "SEL/**/ECT")
        return payload

    def should_backoff(self, status_code: int) -> bool:
        """Check if we should backoff based on status code"""
        if status_code in [429, 403, 503]:
            self.consecutive_blocks += 1
            return True
        else:
            self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
            return False

    def adaptive_delay(self):
        """Sleep for an adaptive amount of time"""
        if self.consecutive_blocks > 0:
            # Exponential backoff
            sleep_time = self.current_delay * (2 ** min(self.consecutive_blocks, 5))
            # But cap it reasonably
            sleep_time = min(sleep_time, 30.0)
            time.sleep(sleep_time)
        else:
            # Normal rate limit
            time.sleep(self.current_delay)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="WAF Evasion Tool")
    parser.add_argument("--url", help="Target URL to detect WAF")
    parser.add_argument("--encode", help="Payload to encode")
    parser.add_argument("--method", default="url", choices=["url", "double_url", "base64", "unicode", "comment"], help="Encoding method")
    
    args = parser.parse_args()
    
    evader = WAFEvader()
    
    if args.url:
        print(f"[*] Detecting WAF for {args.url}...")
        info = evader.detect_waf(args.url)
        if info.detected:
            print(f"[!] WAF Detected: {info.name} (Confidence: {info.confidence})")
            print(f"    Recommended Bypasses: {', '.join(info.bypass_techniques)}")
        else:
            print("[-] No WAF detected or unable to identify.")
            
    if args.encode:
        encoded = evader.encode_payload(args.encode, args.method)
        print(f"\n[*] Encoded Payload ({args.method}):")
        print(f"    {encoded}")
