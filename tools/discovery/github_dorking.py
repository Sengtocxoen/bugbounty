#!/usr/bin/env python3
"""
GitHub/GitLab Dorking Module
Automatically searches public repositories for leaked secrets, credentials, and internal docs.
Searches for target domain mentions in code, commits, issues, and configuration files.
"""

import requests
import time
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime


@dataclass
class DorkFinding:
    """A finding from GitHub/GitLab dorking"""
    platform: str  # github or gitlab
    repository: str
    file_path: str
    match_type: str  # credential, api_key, config, env_file, etc.
    content_snippet: str
    url: str
    severity: str = "medium"  # low, medium, high, critical
    confidence: str = "medium"


@dataclass
class DorkResult:
    """Results from dorking operation"""
    target_domain: str
    findings: List[DorkFinding] = field(default_factory=list)
    repositories_searched: int = 0
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class GitHubDorker:
    """Search GitHub for leaked secrets and internal information"""
    
    def __init__(self, github_token: Optional[str] = None, rate_limit: float = 1.0):
        """
        Initialize GitHub dorker
        
        Args:
            github_token: GitHub personal access token (optional, but recommended for higher rate limits)
            rate_limit: Requests per second
        """
        self.github_token = github_token
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.base_url = "https://api.github.com"
        
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BugBountySecurityResearch/1.0'
        self.session.headers['Accept'] = 'application/vnd.github.v3+json'
        
        if github_token:
            self.session.headers['Authorization'] = f'token {github_token}'
    
    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
    
    def _search_code(self, query: str, max_results: int = 30) -> List[Dict]:
        """Search GitHub code"""
        self._rate_limit_wait()
        
        try:
            url = f"{self.base_url}/search/code"
            params = {
                'q': query,
                'per_page': min(max_results, 100)
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            elif response.status_code == 403:
                # Rate limit hit
                print("  [!] GitHub rate limit reached. Consider using a token.")
                return []
            else:
                return []
                
        except Exception as e:
            print(f"  [!] GitHub search error: {e}")
            return []
    
    def _analyze_content(self, content: str, file_path: str) -> List[Dict]:
        """Analyze file content for sensitive information"""
        findings = []
        
        # Patterns for sensitive data
        patterns = {
            'aws_key': (r'(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 'critical'),
            'api_key': (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'high'),
            'password': (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{5,})["\']', 'high'),
            'secret': (r'(?i)(secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'high'),
            'private_key': (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 'critical'),
            'database_url': (r'(?i)(database_url|db_url|connection_string)\s*[:=]\s*["\']([^"\']+)["\']', 'high'),
            'slack_webhook': (r'https://hooks\.slack\.com/services/[A-Z0-9/]+', 'medium'),
            'github_token': (r'gh[pousr]_[A-Za-z0-9_]{36,}', 'critical'),
        }
        
        for match_type, (pattern, severity) in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                snippet = content[start:end].replace('\n', ' ')
                
                findings.append({
                    'type': match_type,
                    'snippet': snippet,
                    'severity': severity
                })
        
        return findings
    
    def dork_domain(self, domain: str, max_results: int = 50) -> DorkResult:
        """
        Search GitHub for domain-related leaks
        
        Args:
            domain: Target domain (e.g., example.com)
            max_results: Maximum results per query
        """
        result = DorkResult(target_domain=domain)
        
        print(f"\n[*] GitHub Dorking: {domain}")
        print("=" * 60)
        
        # Search queries focusing on high-value targets
        queries = [
            f'{domain} filename:.env',
            f'{domain} filename:config',
            f'{domain} filename:secrets',
            f'{domain} extension:json',
            f'{domain} extension:yml',
            f'{domain} extension:yaml',
            f'{domain} "api_key" OR "apikey"',
            f'{domain} "password" OR "passwd"',
            f'{domain} "SECRET" OR "secret_key"',
            f'{domain} extension:pem',
            f'{domain} "BEGIN PRIVATE KEY"',
        ]
        
        seen_urls = set()
        
        for query in queries:
            print(f"\n  [SEARCH] {query}")
            
            items = self._search_code(query, max_results=20)
            
            for item in items:
                repo_name = item['repository']['full_name']
                file_path = item['path']
                html_url = item['html_url']
                
                # Skip if already seen
                if html_url in seen_urls:
                    continue
                seen_urls.add(html_url)
                
                result.repositories_searched += 1
                
                # Get file content
                self._rate_limit_wait()
                try:
                    # Use raw content URL
                    raw_url = html_url.replace('github.com', 'raw.githubusercontent.com')
                    raw_url = raw_url.replace('/blob/', '/')
                    
                    response = self.session.get(raw_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text
                        
                        # Analyze content
                        content_findings = self._analyze_content(content, file_path)
                        
                        for cf in content_findings:
                            finding = DorkFinding(
                                platform='github',
                                repository=repo_name,
                                file_path=file_path,
                                match_type=cf['type'],
                                content_snippet=cf['snippet'][:200],
                                url=html_url,
                                severity=cf['severity'],
                                confidence='high'
                            )
                            result.findings.append(finding)
                            
                            print(f"    [FOUND] {cf['type']} in {repo_name}/{file_path}")
                            print(f"            Severity: {cf['severity']}")
                            
                except Exception as e:
                    pass  # Skip errors for individual files
        
        print(f"\n  [SUMMARY] Found {len(result.findings)} potential leaks in {result.repositories_searched} files")
        
        return result


class GitLabDorker:
    """Search GitLab for leaked secrets"""
    
    def __init__(self, gitlab_token: Optional[str] = None, rate_limit: float = 1.0):
        """
        Initialize GitLab dorker
        
        Args:
            gitlab_token: GitLab personal access token
            rate_limit: Requests per second
        """
        self.gitlab_token = gitlab_token
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.base_url = "https://gitlab.com/api/v4"
        
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BugBountySecurityResearch/1.0'
        
        if gitlab_token:
            self.session.headers['PRIVATE-TOKEN'] = gitlab_token
    
    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
    
    def _search_projects(self, search: str, max_results: int = 20) -> List[Dict]:
        """Search GitLab projects"""
        self._rate_limit_wait()
        
        try:
            url = f"{self.base_url}/search"
            params = {
                'scope': 'projects',
                'search': search,
                'per_page': max_results
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                return []
                
        except Exception:
            return []
    
    def dork_domain(self, domain: str) -> DorkResult:
        """Search GitLab for domain-related leaks"""
        result = DorkResult(target_domain=domain)
        
        print(f"\n[*] GitLab Dorking: {domain}")
        print("=" * 60)
        
        # Search for projects mentioning the domain
        projects = self._search_projects(domain, max_results=20)
        
        print(f"  [FOUND] {len(projects)} projects mentioning {domain}")
        
        for project in projects:
            project_name = project.get('path_with_namespace', '')
            web_url = project.get('web_url', '')
            
            finding = DorkFinding(
                platform='gitlab',
                repository=project_name,
                file_path='',
                match_type='project_reference',
                content_snippet=f"Project: {project_name}",
                url=web_url,
                severity='low',
                confidence='medium'
            )
            result.findings.append(finding)
            
            print(f"    [FOUND] Project: {project_name}")
        
        result.repositories_searched = len(projects)
        
        return result


def save_dork_results(result: DorkResult, output_file: str):
    """Save dorking results to JSON"""
    import json
    
    data = {
        'target_domain': result.target_domain,
        'scan_time': result.scan_time,
        'repositories_searched': result.repositories_searched,
        'findings_count': len(result.findings),
        'findings': [
            {
                'platform': f.platform,
                'repository': f.repository,
                'file_path': f.file_path,
                'match_type': f.match_type,
                'snippet': f.content_snippet,
                'url': f.url,
                'severity': f.severity,
                'confidence': f.confidence
            }
            for f in result.findings
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="GitHub/GitLab Dorking Tool")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--github-token", help="GitHub personal access token")
    parser.add_argument("--gitlab-token", help="GitLab personal access token")
    parser.add_argument("--platform", choices=['github', 'gitlab', 'both'], default='github',
                       help="Platform to search")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--max-results", type=int, default=50, help="Max results per query")
    
    args = parser.parse_args()
    
    all_findings = []
    
    if args.platform in ['github', 'both']:
        github_dorker = GitHubDorker(github_token=args.github_token)
        github_result = github_dorker.dork_domain(args.domain, max_results=args.max_results)
        all_findings.extend(github_result.findings)
    
    if args.platform in ['gitlab', 'both']:
        gitlab_dorker = GitLabDorker(gitlab_token=args.gitlab_token)
        gitlab_result = gitlab_dorker.dork_domain(args.domain)
        all_findings.extend(gitlab_result.findings)
    
    # Print summary
    print("\n" + "="*60)
    print("DORKING SUMMARY")
    print("="*60)
    
    if all_findings:
        critical = [f for f in all_findings if f.severity == 'critical']
        high = [f for f in all_findings if f.severity == 'high']
        
        print(f"\nTotal findings: {len(all_findings)}")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        
        if critical:
            print("\n[!] CRITICAL FINDINGS:")
            for f in critical[:5]:
                print(f"  - {f.match_type} in {f.repository}")
                print(f"    URL: {f.url}")
    else:
        print("\nNo findings.")
    
    if args.output:
        # Combine results
        combined = DorkResult(target_domain=args.domain, findings=all_findings)
        save_dork_results(combined, args.output)
