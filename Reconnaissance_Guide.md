# Reconnaissance & Target Discovery Guide

## Overview

This guide provides specific commands and techniques for discovering and mapping targets in both Amazon VRP and Shopify bug bounty programs.

---

## AMAZON VRP - RECONNAISSANCE

### 1. Subdomain Enumeration

#### Primary Domains to Target
```bash
# Major Amazon domains (wildcard scope)
amazon.com
amazon.co.uk
amazon.in
amazon.de
amazon.fr
amazon.co.jp
amazon.ca
# ... and all other country-specific domains
```

#### Subdomain Discovery Commands

**Using Amass:**
```bash
# Install: go install -v github.com/owasp-amass/amass/v4/...@master

# Passive enumeration
amass enum -passive -d amazon.com -o amazon_subdomains.txt

# Active enumeration (be careful with rate limits!)
amass enum -active -d amazon.com -o amazon_subdomains_active.txt

# Multiple domains
for domain in amazon.com amazon.co.uk amazon.in; do
    amass enum -passive -d $domain -o ${domain}_subs.txt
done
```

**Using Subfinder:**
```bash
# Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

subfinder -d amazon.com -o amazon_subs.txt
subfinder -dL amazon_domains.txt -o all_amazon_subs.txt
```

**Using Assetfinder:**
```bash
# Install: go get -u github.com/tomnomnom/assetfinder

assetfinder amazon.com | tee amazon_assets.txt
```

**Using Sublist3r:**
```bash
python3 sublist3r.py -d amazon.com -o amazon_sublist3r.txt
```

#### Filtering Out-of-Scope Domains

**Critical Filters:**
```bash
# Remove AWS-related subdomains
grep -v "aws" amazon_subs.txt > amazon_filtered.txt

# Remove .a2z domains
grep -v "\.a2z\." amazon_filtered.txt > amazon_filtered2.txt

# Remove .dev domains
grep -v "\.dev" amazon_filtered2.txt > amazon_filtered3.txt

# Remove test/staging environments
grep -vE "(test|qa|staging|preprod|gamma|beta|integ)" amazon_filtered3.txt > amazon_final.txt

# Remove user-aliases and regions
grep -vE "(user-aliases|us-east|us-west|eu-west)" amazon_final.txt > amazon_clean.txt
```

**One-liner filter:**
```bash
cat amazon_subs.txt | grep -vE "(aws|\.a2z\.|\.dev|test|qa|staging|preprod|gamma|beta|integ|user-aliases|us-east|us-west)" > amazon_in_scope.txt
```

### 2. Technology Stack Identification

**Using Wappalyzer:**
```bash
# Browser extension or CLI
wappalyzer https://www.amazon.com
```

**Using WhatWeb:**
```bash
whatweb https://www.amazon.com -v
```

**Using BuiltWith:**
- Use browser extension or visit builtwith.com

### 3. Endpoint Discovery

**Using Wayback Machine:**
```bash
# Install: go install github.com/lc/gau/v2/cmd/gau@latest

# Get historical URLs
gau amazon.com | tee amazon_wayback.txt

# Filter for interesting endpoints
gau amazon.com | grep -E "(api|admin|auth|login|register|reset|payment|order)" > amazon_interesting.txt
```

**Using Waybackurls:**
```bash
# Install: go install github.com/tomnomnom/waybackurls@latest

waybackurls amazon.com | tee amazon_waybackurls.txt
```

**Using Katana (Crawling):**
```bash
# Install: go install github.com/projectdiscovery/katana/cmd/katana@latest

katana -u https://www.amazon.com -o amazon_crawl.txt
katana -u https://www.amazon.com -js-crawl -o amazon_js_crawl.txt
```

**Using ffuf (Directory Brute-Forcing):**
```bash
# IMPORTANT: Rate limit to 5 req/sec for Amazon!
# Use delay: -t 1 -rate 5

ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://www.amazon.com/FUZZ \
     -t 1 \
     -rate 5 \
     -H "User-Agent: amazonvrpresearcher_yourh1username" \
     -o amazon_dirs.json

# API endpoint discovery
ffuf -w /usr/share/wordlists/dirb/common.txt \
     -u https://www.amazon.com/api/v1/FUZZ \
     -t 1 \
     -rate 5 \
     -H "User-Agent: amazonvrpresearcher_yourh1username"
```

### 4. API Discovery

**GraphQL Endpoints:**
```bash
# Common GraphQL endpoints
- /graphql
- /api/graphql
- /v1/graphql
- /graphql/v1

# Test with introspection query
curl -X POST https://www.amazon.com/graphql \
  -H "Content-Type: application/json" \
  -H "User-Agent: amazonvrpresearcher_yourh1username" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

**REST API Discovery:**
```bash
# Look for common patterns
- /api/v1/*
- /api/v2/*
- /rest/*
- /v1/*
- /v2/*

# Use gau/waybackurls to find API endpoints
gau amazon.com | grep -E "/api/|/v[0-9]/" > amazon_apis.txt
```

**Mobile App API Reverse Engineering:**
```bash
# Android APK Analysis
jadx-gui com.amazon.mShop.android.shopping.apk

# Look for:
# - API endpoints in strings.xml
# - Network security config
# - Certificate pinning
# - API keys/tokens

# iOS Analysis
# Use class-dump or Hopper to analyze binary
```

### 5. Parameter Discovery

**Using Arjun:**
```bash
# Install: pip3 install arjun

arjun -u https://www.amazon.com/search?q=test -o amazon_params.txt
```

**Using ParamSpider:**
```bash
# Install: pip3 install paramspider

paramspider -d amazon.com -o amazon_params.txt
```

**Using x8:**
```bash
# Install: cargo install x8

x8 -u "https://www.amazon.com/search" -w /path/to/wordlist.txt
```

### 6. JavaScript File Analysis

**Extract JS files:**
```bash
# From waybackurls
waybackurls amazon.com | grep "\.js$" > amazon_js_files.txt

# From gau
gau amazon.com | grep "\.js$" > amazon_js_files.txt

# Analyze for endpoints, API keys, secrets
cat amazon_js_files.txt | while read url; do
    echo "=== $url ==="
    curl -s "$url" | grep -E "(api|endpoint|token|key|secret)" | head -20
done
```

### 7. GenAI/LLM Feature Discovery

**Look for:**
- Chat interfaces
- AI-powered search
- Product recommendations
- Virtual assistants
- AI customer service

**Discovery:**
```bash
# Search for AI-related endpoints
gau amazon.com | grep -iE "(ai|chat|assistant|genai|llm|prompt)" > amazon_ai_features.txt

# Look in JavaScript files
cat amazon_js_files.txt | while read url; do
    curl -s "$url" | grep -iE "(ai|chat|assistant|genai|llm)" && echo "$url"
done
```

---

## SHOPIFY - RECONNAISSANCE

### 1. In-Scope Asset Discovery

**Official Sources:**
- Check Shopify's scope page regularly
- Review Shopify changelog: https://changelog.shopify.com/
- Check Partners Blog: https://www.shopify.ca/partners/blog/

**Common In-Scope Assets:**
```
- *.shopify.com (specific subdomains)
- partners.shopify.com
- admin.shopify.com
- checkout.shopify.com
- *.myshopify.com (your test stores only!)
```

### 2. API Endpoint Discovery

**GraphQL API:**
```bash
# Shopify uses GraphQL extensively
# Common endpoints:
- https://admin.shopify.com/store/{shop}/graphql.json
- https://partners.shopify.com/{partner_id}/graphql

# Introspection query
curl -X POST https://admin.shopify.com/store/YOUR_STORE/graphql.json \
  -H "Content-Type: application/json" \
  -H "X-Shopify-Access-Token: YOUR_TOKEN" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

**REST API:**
```bash
# Shopify Admin API
- https://{shop}.myshopify.com/admin/api/{version}/*

# Common endpoints:
- /admin/api/2024-01/products.json
- /admin/api/2024-01/orders.json
- /admin/api/2024-01/customers.json
- /admin/api/2024-01/webhooks.json
```

### 3. Partner Portal Discovery

**Key Areas:**
- Partner dashboard
- App development tools
- Store management
- Analytics
- Billing

**Discovery:**
```bash
# Use your test account to explore
# Map out all accessible endpoints
# Test for privilege escalation
```

### 4. Test Store Setup

**Create Multiple Test Stores:**
```bash
# Store 1: Basic store
# Store 2: Store with apps
# Store 3: Store with custom theme
# Store 4: Partner account with multiple stores

# Test isolation between stores
# Look for IDOR vulnerabilities
```

### 5. Webhook Discovery

**Find Webhook Endpoints:**
```bash
# In your test store admin:
# Settings > Notifications > Webhooks

# Test webhook manipulation
# SSRF via webhook URLs
# Authorization bypass
```

---

## COMMON RECON TECHNIQUES (Both Programs)

### 1. Certificate Transparency Logs

```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%.amazon.com&output=json" | jq -r '.[].name_value' | sort -u

# Using certspotter
certspotter amazon.com
```

### 2. DNS Enumeration

```bash
# Using dnsrecon
dnsrecon -d amazon.com -t std

# Using dnsenum
dnsenum amazon.com
```

### 3. Port Scanning (Use with Caution!)

```bash
# IMPORTANT: Only scan in-scope assets
# Use rate limiting
# Don't scan AWS IP ranges

nmap -sS -T2 -p- --max-rate 5 target.amazon.com
```

### 4. GitHub/GitLab Dorking

**Search for:**
- API keys
- Secrets
- Internal endpoints
- Test credentials

**GitHub Dorks:**
```
site:github.com amazon.com API_KEY
site:github.com shopify.com password
site:github.com "amazon.com" "api"
site:github.com "shopify.com" "secret"
```

### 5. Shodan/Censys Search

**Be Careful:** Shodan may show AWS customer assets, not Amazon-owned!

**Amazon:**
```
org:"Amazon.com"
ssl.cert.subject.cn:*.amazon.com
```

**Shopify:**
```
org:"Shopify"
ssl.cert.subject.cn:*.shopify.com
```

---

## AUTOMATION SCRIPTS

### Amazon Subdomain Enumeration Script

```bash
#!/bin/bash
# amazon_recon.sh

DOMAIN=$1
OUTPUT_DIR="amazon_recon_$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

echo "[+] Starting reconnaissance for $DOMAIN"

# Subdomain enumeration
echo "[+] Running subfinder..."
subfinder -d $DOMAIN -o $OUTPUT_DIR/subfinder.txt

echo "[+] Running assetfinder..."
assetfinder $DOMAIN >> $OUTPUT_DIR/assetfinder.txt

echo "[+] Running amass (passive)..."
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/amass.txt

# Combine and deduplicate
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subs.txt

# Filter out-of-scope
echo "[+] Filtering out-of-scope domains..."
cat $OUTPUT_DIR/all_subs.txt | grep -vE "(aws|\.a2z\.|\.dev|test|qa|staging|preprod|gamma|beta|integ|user-aliases|us-east|us-west)" > $OUTPUT_DIR/in_scope.txt

# Wayback URLs
echo "[+] Getting wayback URLs..."
gau $DOMAIN | tee $OUTPUT_DIR/wayback.txt

# Technology detection
echo "[+] Detecting technologies..."
whatweb https://$DOMAIN -v > $OUTPUT_DIR/tech_stack.txt

echo "[+] Reconnaissance complete! Results in $OUTPUT_DIR/"
```

### Shopify API Discovery Script

```bash
#!/bin/bash
# shopify_api_discovery.sh

STORE=$1
OUTPUT_DIR="shopify_recon_$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

echo "[+] Discovering APIs for $STORE"

# GraphQL introspection
echo "[+] Testing GraphQL..."
curl -X POST "https://$STORE.myshopify.com/admin/api/graphql.json" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}' \
  -o $OUTPUT_DIR/graphql_introspection.json 2>/dev/null

# REST API discovery
echo "[+] Testing REST API..."
for endpoint in products orders customers webhooks; do
    curl -s "https://$STORE.myshopify.com/admin/api/2024-01/$endpoint.json" \
      -o $OUTPUT_DIR/${endpoint}.json 2>/dev/null
done

echo "[+] API discovery complete! Results in $OUTPUT_DIR/"
```

---

## ORGANIZING YOUR FINDINGS

### Directory Structure

```
bugbounty/
├── amazon/
│   ├── recon/
│   │   ├── subdomains/
│   │   ├── endpoints/
│   │   ├── apis/
│   │   └── js_files/
│   ├── targets/
│   │   ├── target1/
│   │   │   ├── notes.md
│   │   │   ├── screenshots/
│   │   │   └── poc/
│   └── reports/
├── shopify/
│   ├── recon/
│   ├── test_stores/
│   └── reports/
└── tools/
```

### Note-Taking Template

```markdown
# Target: [URL/Subdomain]

## Discovery Date: [Date]

## Technology Stack:
- Framework: 
- Server: 
- CDN: 
- APIs: 

## Endpoints Found:
- /api/v1/...
- /admin/...
- /graphql

## Interesting Features:
- Authentication flow
- Payment processing
- File upload
- AI/GenAI features

## Potential Vulnerabilities:
1. [Finding 1]
2. [Finding 2]

## Testing Notes:
- [Date] - Tested X, found Y
- [Date] - Verified Z

## Screenshots:
- [Path to screenshots]
```

---

## RATE LIMITING REMINDERS

### Amazon VRP
- **MAX 5 requests/second**
- Always include User-Agent: `amazonvrpresearcher_yourh1username`
- Use delays in scripts: `sleep 0.2` between requests

### Shopify
- Be respectful with rate limits
- Use official API rate limits as guideline

---

## NEXT STEPS AFTER RECON

1. **Prioritize Targets:**
   - Admin panels
   - Authentication endpoints
   - Payment processing
   - API endpoints
   - File upload functions

2. **Map Attack Surface:**
   - Authentication flows
   - Authorization checks
   - Input points
   - Output points

3. **Start Testing:**
   - Follow the testing checklist
   - Focus on high-value vulnerabilities
   - Document everything

---

**Remember:** Reconnaissance is an ongoing process. New subdomains and endpoints are discovered regularly. Keep your recon data updated!

