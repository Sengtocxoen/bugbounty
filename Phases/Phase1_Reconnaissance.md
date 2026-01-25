# Phase 1: Reconnaissance

**Goal:** Discover and enumerate all in-scope assets before testing begins.

---

## Overview

Reconnaissance is the foundation of successful bug bounty hunting. This phase focuses on building a comprehensive map of the target's attack surface without actively exploiting anything.

```
+-------------------+     +-------------------+     +-------------------+
|  Passive Recon    | --> |  Active Recon     | --> |  Output           |
+-------------------+     +-------------------+     +-------------------+
| - CT logs         |     | - DNS bruteforce  |     | - Subdomain list  |
| - Search engines  |     | - Port scanning   |     | - Endpoint list   |
| - Public sources  |     | - Tech detection  |     | - Tech stack      |
| - Historical data |     | - Crawling        |     | - Attack vectors  |
+-------------------+     +-------------------+     +-------------------+
```

---

## Wiz 5-Phase Reconnaissance Methodology

### Phase 1.1: Passive Subdomain Discovery

**Objective:** Gather subdomains without touching the target.

```bash
# Using the integrated wiz_recon module
python tools/wiz_recon.py example.com

# With program settings (Amazon)
python tools/wiz_recon.py amazon.com -p amazon -u yourh1username

# Manual with subfinder
subfinder -d example.com -all -o passive-subdomains.txt
```

**Sources Queried:**
- Certificate Transparency logs (crt.sh)
- subfinder (60+ sources)
- HackerTarget
- AlienVault OTX
- URLScan.io
- RapidDNS
- CertSpotter
- BufferOver.run

### Phase 1.2: DNS Resolution

**Objective:** Filter out non-resolving domains.

```bash
# Filter using puredns
cat passive-subdomains.txt | puredns resolve | tee resolved.txt

# Expected result: ~75% resolution rate
# Example: 1600 passive -> 1200 active
```

### Phase 1.3: Active DNS Discovery

**Objective:** Find subdomains not in passive sources.

```bash
# DNS Bruteforce
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w bruteforce.txt

# DNS Permutation with alterx
cat known-subdomains.txt | alterx | puredns resolve | tee permutations.txt
```

**Wordlist Recommendations:**
| Mode | Size | Use Case |
|------|------|----------|
| Quick | ~40 | Initial scan |
| Medium | ~100 | Default |
| Thorough | ~300+ | Deep dive |

### Phase 1.4: Root Domain Discovery

**Objective:** Find additional company-owned domains.

```bash
# Reverse WHOIS (requires API)
# Services: whoxy.com, domaintools.com

# Check Crunchbase acquisitions
# crunchbase.com/organization/[company]/acquisitions

# GitHub domain mining
# Search for internal domain references
```

### Phase 1.5: Public Exposure Probing

**Objective:** Extract metadata from live targets.

```bash
# Using httpx
cat resolved.txt | httpx -title -status-code -ip -cname -tech-detect -o metadata.txt

# Status Code Actions:
# 200 - Test immediately
# 403/404 - Fuzz paths (/admin, /api, /backup)
# 500 - Investigate errors
```

---

## Program-Specific Filtering

### Amazon VRP

**CRITICAL: Filter out-of-scope domains:**

```bash
# One-liner filter
cat subdomains.txt | grep -vE "(aws|\.a2z\.|\.dev|test|qa|staging|preprod|gamma|beta|integ|user-aliases)" > in_scope.txt
```

**Out of Scope:**
- `*aws*` - Any AWS subdomain
- `*.a2z.*` - Internal domains
- `*.dev` - Development domains
- `test|qa|staging|preprod|gamma|beta|integ` - Test environments

### Shopify

**Focus on documented in-scope assets:**
- Review Shopify's official scope page
- Partner portal endpoints
- Your test stores only

---

## Endpoint Discovery

### Historical Data

```bash
# Using gau (Get All URLs)
gau example.com | tee wayback_urls.txt

# Filter interesting endpoints
gau example.com | grep -E "(api|admin|auth|login|payment)" > interesting.txt

# Using waybackurls
waybackurls example.com | tee historical_urls.txt
```

### Active Crawling

```bash
# Using Katana
katana -u https://example.com -o crawl_results.txt

# With JavaScript crawling
katana -u https://example.com -js-crawl -o js_crawl.txt
```

### Directory Discovery

```bash
# Using ffuf (RESPECT RATE LIMITS!)
# Amazon: Max 5 req/sec with required User-Agent

ffuf -w wordlist.txt \
     -u https://target.com/FUZZ \
     -t 1 \
     -rate 5 \
     -H "User-Agent: amazonvrpresearcher_yourh1username" \
     -o dirs.json
```

---

## Technology Detection

```bash
# Using httpx tech detection
echo "https://example.com" | httpx -tech-detect

# Using WhatWeb
whatweb https://example.com -v

# Using Wappalyzer (browser extension or CLI)
wappalyzer https://example.com
```

**Key Technologies to Identify:**
- Web framework (React, Angular, Django, Rails)
- Server software (nginx, Apache, IIS)
- CDN provider
- API technologies (GraphQL, REST)
- Authentication systems
- CMS platforms

---

## API Discovery

### GraphQL Endpoints

```bash
# Common paths to check:
/graphql
/api/graphql
/v1/graphql
/graphql/v1

# Introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

### REST API Endpoints

```bash
# Find from historical data
gau example.com | grep -E "/api/|/v[0-9]/" > api_endpoints.txt

# Common patterns:
/api/v1/*
/api/v2/*
/rest/*
```

---

## JavaScript Analysis

```bash
# Extract JS files
gau example.com | grep "\.js$" > js_files.txt

# Analyze for secrets and endpoints
cat js_files.txt | while read url; do
    echo "=== $url ==="
    curl -s "$url" | grep -E "(api|endpoint|token|key|secret)" | head -20
done
```

---

## Output Organization

### Directory Structure

```
Program/
└── Phase1_Recon/
    ├── subdomains/
    │   ├── passive.txt
    │   ├── resolved.txt
    │   ├── bruteforce.txt
    │   └── final_inscope.txt
    ├── endpoints/
    │   ├── wayback.txt
    │   ├── crawl.txt
    │   ├── api_endpoints.txt
    │   └── interesting.txt
    ├── tech_stack/
    │   ├── technologies.txt
    │   └── metadata.json
    └── js_files/
        ├── js_urls.txt
        └── extracted_secrets.txt
```

### Subdomain Summary Template

```markdown
# Recon Summary: [Target]
Date: [YYYY-MM-DD]

## Statistics
- Passive subdomains found: X
- Resolved subdomains: Y
- In-scope after filtering: Z

## Key Findings
- [Finding 1]
- [Finding 2]

## High-Priority Targets
1. admin.target.com - Admin panel
2. api.target.com - API endpoint
3. payments.target.com - Payment system

## Technologies Detected
- Framework: X
- Server: Y
- CDN: Z

## Next Steps (Phase 2)
- [ ] Map attack surface for high-priority targets
- [ ] Identify authentication flows
- [ ] Catalog API endpoints
```

---

## Tools Quick Reference

| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| puredns | DNS resolution | `go install github.com/d3mondev/puredns/v2@latest` |
| alterx | DNS permutation | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| httpx | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | Historical URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| ffuf | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |

---

## Checklist

### Before Starting
- [ ] Read program scope and rules
- [ ] Set up required User-Agent (if needed)
- [ ] Configure rate limiting
- [ ] Prepare filtering rules for out-of-scope

### During Recon
- [ ] Run passive subdomain enumeration
- [ ] Resolve and filter subdomains
- [ ] Run active DNS discovery
- [ ] Probe for technology stack
- [ ] Discover endpoints and APIs
- [ ] Analyze JavaScript files
- [ ] Check for exposed files

### After Recon
- [ ] Filter out-of-scope assets
- [ ] Organize findings by priority
- [ ] Document technology stack
- [ ] Prepare targets list for Phase 2

---

## Next Phase

Once reconnaissance is complete, proceed to [Phase 2: Analysis](Phase2_Analysis.md) to map the attack surface and identify entry points.
