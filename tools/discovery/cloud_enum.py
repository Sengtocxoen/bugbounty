#!/usr/bin/env python3
"""
Cloud Storage Enumeration Module
Enumerates and tests cloud storage buckets (S3, Azure Blob, Google Cloud Storage).
Generates bucket name permutations based on target domain and checks for:
- Existence
- Public access permissions (Read/Write/List)
- Cloud provider identification
"""

import re
import time
import threading
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import xml.etree.ElementTree as ET

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from utils.config import get_amazon_config, get_shopify_config

@dataclass
class BucketResult:
    """Result of a cloud bucket check"""
    name: str
    provider: str  # aws, azure, gcp
    url: str
    exists: bool = False
    status_code: int = 0
    permissions: List[str] = field(default_factory=list)  # read, write, list
    file_count: int = 0  # if listable
    size_bytes: int = 0  # if listable
    auth_required: bool = False
    context: str = ""  # usage context if known (assets, backup, etc.)

@dataclass
class CloudEnumResult:
    """Results from cloud enumeration"""
    target: str
    buckets: List[BucketResult] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    total_checked: int = 0

# Common patterns for bucket naming
BUCKET_PERMUTATIONS = [
    "{name}",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-images",
    "{name}-img",
    "{name}-files",
    "{name}-public",
    "{name}-dev",
    "{name}-development",
    "{name}-staging",
    "{name}-prod",
    "{name}-production",
    "{name}-test",
    "{name}-testing",
    "{name}-backup",
    "{name}-backups",
    "{name}-archive",
    "{name}-logs",
    "{name}-data",
    "{name}-database",
    "{name}-db",
    "{name}-secure",
    "{name}-private",
    "{name}-admin",
    "{name}-internal",
    "{name}-corp",
    "{name}-conf",
    "{name}-config",
    "{name}-upload",
    "{name}-uploads",
    "{name}-download",
    "{name}-downloads",
    "assets-{name}",
    "static-{name}",
    "dev-{name}",
    "test-{name}",
    "prod-{name}",
    "staging-{name}",
]

class CloudEnumerator:
    def __init__(self, rate_limit: float = 10.0, user_agent: str = "BugBountyResearcher",
                 max_threads: int = 10):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()
        self.user_agent = user_agent
        self.max_threads = max_threads
        
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': '*/* for bug bounty research',
        })

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        # Rate limiting logic is slightly relaxed for cloud providers as they can handle load,
        # but we still want to be polite and avoid IP bans.
        # Since we use threads, we need to be careful.
        self._rate_limit_wait()
        try:
            return self.session.request(method, url, timeout=5, **kwargs)
        except Exception:
            return None

    def generate_bucket_names(self, domain: str) -> List[Tuple[str, str]]:
        """Generate potential bucket names from domain"""
        names = []
        
        # Extract base name (e.g., example from example.com)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_name = parts[-2]
            # Also handle full domain without tld
            full_name = domain.replace('.', '-')
            # And straight domain
            domain_name = domain
            
            cleaned_names = [base_name]
            if base_name != full_name:
                cleaned_names.append(full_name)
            if base_name != domain_name:
                cleaned_names.append(domain_name)
                
            for name in cleaned_names:
                for perm in BUCKET_PERMUTATIONS:
                    bucket_name = perm.format(name=name)
                    context = perm.replace("{name}", "").strip("-")
                    if not context:
                        context = "root"
                    names.append((bucket_name, context))
                    
        return list(set(names)) # Deduplicate

    def check_s3_bucket(self, bucket_name: str, context: str) -> Optional[BucketResult]:
        """Check AWS S3 bucket"""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        response = self._request(url)
        
        if not response:
            return None
            
        # 404 = Does not exist
        if response.status_code == 404:
            return None
            
        result = BucketResult(
            name=bucket_name,
            provider="aws",
            url=url,
            exists=True,
            status_code=response.status_code,
            context=context
        )
        
        # Check permissions
        if response.status_code == 200:
            result.permissions.append("read")
            # Check for listing (ListObjects)
            if "ListBucketResult" in response.text:
                result.permissions.append("list")
                # Parse count/size if listable
                try:
                    root = ET.fromstring(response.text)
                    # Namespace handling might be needed
                    keys = root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                    if not keys:
                        # Try without namespace
                        keys = root.findall("Key")
                    result.file_count = len(keys)
                except:
                    pass
        elif response.status_code == 403:
            result.auth_required = True
            
        return result

    def check_azure_blob(self, blob_name: str, context: str) -> Optional[BucketResult]:
        """Check Azure Blob Storage"""
        # Azure usually follows: https://<storage-account>.blob.core.windows.net/<container>
        # But we check for storage account existence first
        url = f"https://{blob_name}.blob.core.windows.net"
        
        # Just checking the root often returns 400 InvalidQueryParameterValue or similar if exists
        # detailed check involves checking a common container or just seeing DNS resolution
        # For HTTP check:
        response = self._request(url)
        
        if not response:
            return None
            
        # Does not exist (usually DNS fails, or 404)
        # However, Azure custom domains make this tricky via HTTP.
        # Direct blob URL checks:
        if response.status_code == 404:
            # Check if it's "The specified account does not exist" or just "Resource not found"
            if "AccountNameInvalid" in response.text or "The specified account does not exist" in response.text:
                return None
            
        result = BucketResult(
            name=blob_name,
            provider="azure",
            url=url,
            exists=True,
            status_code=response.status_code,
            context=context
        )
        
        if response.status_code == 200:
            result.permissions.append("read") # public container listing enabled at root? rare
        elif response.status_code == 403:
             result.auth_required = True
             
        # Check for listing
        list_url = f"{url}/?comp=list"
        list_response = self._request(list_url)
        if list_response and list_response.status_code == 200:
            result.permissions.append("list")
            
        return result

    def check_gcs_bucket(self, bucket_name: str, context: str) -> Optional[BucketResult]:
        """Check Google Cloud Storage bucket"""
        url = f"https://storage.googleapis.com/{bucket_name}"
        response = self._request(url)
        
        if not response:
            return None
            
        if response.status_code == 404:
            if "NoSuchBucket" in response.text:
                return None
                
        result = BucketResult(
            name=bucket_name,
            provider="gcp",
            url=url,
            exists=True,
            status_code=response.status_code,
            context=context
        )
        
        if response.status_code == 200:
            result.permissions.append("read")
            if "ListBucketResult" in response.text:
                result.permissions.append("list")
        elif response.status_code == 403:
            result.auth_required = True
            
        return result

    def enumerate(self, target_domain: str) -> CloudEnumResult:
        """Run enumeration for all providers"""
        result = CloudEnumResult(target=target_domain)
        bucket_names = self.generate_bucket_names(target_domain)
        result.total_checked = len(bucket_names) * 3  # 3 providers
        
        print(f"[*] Cloud Enumeration: Checking {len(bucket_names)} permutations for {target_domain}...")
        
        # Use ThreadPoolExecutor for concurrent checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for name, context in bucket_names:
                # Schedule checks for each provider
                futures.append(executor.submit(self.check_s3_bucket, name, context))
                futures.append(executor.submit(self.check_azure_blob, name, context))
                futures.append(executor.submit(self.check_gcs_bucket, name, context))
                
            for future in concurrent.futures.as_completed(futures):
                try:
                    bucket_res = future.result()
                    if bucket_res:
                        print(f"  [FOUND] {bucket_res.provider.upper()}: {bucket_res.url} ({bucket_res.context})")
                        if "list" in bucket_res.permissions:
                            print(f"    [CRITICAL] Bucket is LISTABLE!")
                        result.buckets.append(bucket_res)
                except Exception as e:
                    pass
                    
        return result

    def save_results(self, result: CloudEnumResult, output_file: str):
        """Save results to JSON"""
        import json
        
        data = {
            "target": result.target,
            "scan_time": result.scan_time,
            "buckets_found": len(result.buckets),
            "buckets": [
                {
                    "name": b.name,
                    "provider": b.provider,
                    "url": b.url,
                    "permissions": b.permissions,
                    "auth_required": b.auth_required,
                    "context": b.context
                }
                for b in result.buckets
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"[*] Results saved to {output_file}")

if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Cloud Storage Enumeration Tool")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--output", "-o", help="Output JSON file")
    
    args = parser.parse_args()
    
    enumerator = CloudEnumerator(max_threads=args.threads)
    results = enumerator.enumerate(args.target)
    
    print(f"\n[Summary] Found {len(results.buckets)} buckets.")
    
    if args.output:
        enumerator.save_results(results, args.output)
