# Gemini.md

Instructions for Google Gemini when working with this bug bounty workspace.

---

## Project Overview

This is a bug bounty research workspace containing:
- **Program Policies:** Amazon VRP and Shopify Bug Bounty program rules
- **Security Tools:** Python-based vulnerability scanners and utilities
- **Documentation:** Testing strategies, recon guides, and checklists

---

## Directory Structure

```
bugbounty/
├── Amazon/Overview.md          # Amazon VRP policy (MUST READ)
├── Shopify/Overview.md         # Shopify BBP policy (MUST READ)
├── Testing_Strategy.md         # Testing approaches
├── Reconnaissance_Guide.md     # Recon techniques
├── Quick_Reference_Checklist.md # Daily checklists
├── tools/                      # Security testing tools
│   ├── scanner.py              # Main scanner
│   ├── subdomain_discovery.py  # Subdomain enum
│   ├── web_hacking_2025/       # Advanced scanner module
│   └── [other tools]
├── CLAUDE.md                   # Instructions for Claude AI
└── Gemini.md                   # This file
```

---

## Critical Program Rules

### Amazon VRP - MANDATORY

| Requirement | Value |
|-------------|-------|
| User-Agent | `amazonvrpresearcher_<h1username>` |
| Rate Limit | **5 requests/second MAX** |
| Email | `<h1username>@wearehackerone.com` |
| Third-party tools | **PROHIBITED** (self-host only) |

**In Scope:** `*.amazon` (retail marketplaces), mobile apps

**Out of Scope:**
- `aws` subdomains
- `.a2z` and `.dev` domains
- test/staging/qa/preprod environments

### Shopify BBP - MANDATORY

| Requirement | Value |
|-------------|-------|
| Registration | https://partners.shopify.com/signup/bugbounty |
| Email | `<h1username>@wearehackerone.com` |
| Testing | **ONLY stores you created** |

**Forbidden:**
- Testing live merchant stores = DISQUALIFICATION
- Contacting Shopify Support = POTENTIAL BAN

---

## Tools Reference

### Main Scanner

```bash
cd tools

# Amazon VRP scan
python -m web_hacking_2025.run target.amazon.com \
  --program amazon --h1-user YOUR_USERNAME

# Shopify scan
python -m web_hacking_2025.run your-store.myshopify.com \
  --program shopify --h1-user YOUR_USERNAME

# Specific techniques
python -m web_hacking_2025.run target.com \
  --techniques smuggling,ssrf,xss
```

### Available Techniques (11 total)

1. `smuggling` - HTTP Request Smuggling
2. `cache` - Web Cache Poisoning
3. `auth` - Authentication Bypass
4. `xss` - XSS/CSRF/Clickjacking
5. `parser` - XXE/Parser Attacks
6. `inject` - SSTI/SQLi/Command Injection
7. `ssrf` - Server-Side Request Forgery
8. `xsleaks` - Cross-Site Leaks
9. `framework` - Framework Vulnerabilities
10. `deser` - Deserialization
11. `protocol` - Protocol Attacks

---

## Guidelines for Assisting

### When Helping with This Project:

**Always:**
- Verify targets are in-scope before suggesting tests
- Include proper User-Agent headers for Amazon
- Enforce rate limiting (5 req/s max for Amazon)
- Use `@wearehackerone.com` email format
- Recommend self-hosted infrastructure only
- Check program Overview.md files for specific rules

**Never:**
- Suggest testing AWS, .a2z, or .dev domains
- Recommend third-party testing services (XSS Hunter, etc.)
- Suggest testing Shopify stores user doesn't own
- Ignore program-specific restrictions
- Recommend contacting support channels for testing

### When Writing Code:

```python
# Always include for Amazon scans:
headers = {
    'User-Agent': 'amazonvrpresearcher_<username>'
}

# Always rate limit:
import time
time.sleep(0.2)  # 5 requests/second max
```

### When Reviewing Findings:

1. Is target explicitly in-scope?
2. Does vulnerability have real security impact?
3. Is PoC functional (not theoretical)?
4. Does severity match program guidelines?
5. Are all program rules followed?

---

## High-Value Vulnerabilities

### Critical (Highest Bounty)
- Remote Code Execution (RCE)
- SQL Injection
- XXE (XML External Entity)
- High-impact XSS (stored, account takeover)

### High
- SSRF (Server-Side Request Forgery)
- Authentication/Authorization Bypass
- Privilege Escalation
- Critical IDOR

### Medium
- Directory Traversal / LFI
- CORS Misconfiguration
- CSRF with impact
- Information Disclosure

### Not Eligible (Don't Waste Time)
- Clickjacking, Self-XSS
- Missing security headers
- Login/logout CSRF
- Scanner-only outputs
- DOS/DDOS

---

## Quick Commands

```bash
# Subdomain discovery
python tools/subdomain_discovery.py amazon.com

# General scan
python tools/run_scan.py https://target.com

# Scope validation
python tools/scope_validator.py "https://target.amazon.com"

# Deep scan
python tools/deep_scan.py https://target.com
```

---

## Documentation Files

| File | Purpose |
|------|---------|
| `Amazon/Overview.md` | Complete Amazon VRP policy |
| `Shopify/Overview.md` | Complete Shopify BBP policy |
| `Testing_Strategy.md` | Strategic testing approaches |
| `Reconnaissance_Guide.md` | Recon commands and techniques |
| `Quick_Reference_Checklist.md` | Daily testing checklists |
| `tools/web_hacking_2025/README.md` | Advanced scanner documentation |

---

## Common Tasks

### Adding a New Program

1. Create directory: `<ProgramName>/`
2. Create `Overview.md` with policy from HackerOne/Bugcrowd
3. Document: scope, exclusions, rules, severity levels
4. Update AI instruction files (CLAUDE.md, Gemini.md)

### Preparing a Report

1. Verify target is in-scope
2. Create working Proof of Concept
3. Write clear reproduction steps
4. Document security impact
5. Add screenshots/video evidence
6. Calculate severity per program guidelines

---

## Remember

1. **Scope First** - Always verify before testing
2. **Rate Limits** - Violations = potential ban
3. **Self-Host Only** - No third-party services for Amazon
4. **Own Stores Only** - Shopify testing restriction
5. **Document Everything** - Evidence is critical
6. **Report Responsibly** - Follow disclosure rules
