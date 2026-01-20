# CLAUDE.md

Instructions for Claude Code (claude.ai/code) when working with this bug bounty workspace.

---

## Quick Reference

| Item | Value |
|------|-------|
| **Purpose** | Bug bounty research workspace |
| **Programs** | Amazon VRP, Shopify BBP |
| **Tools Location** | `tools/` directory |
| **Scan Command** | `python -m web_hacking_2025.run` |

---

## Project Structure

```
bugbounty/
├── Amazon/Overview.md          # Amazon VRP program policy
├── Shopify/Overview.md         # Shopify BBP program policy
├── Testing_Strategy.md         # Strategic testing approaches
├── Reconnaissance_Guide.md     # Recon commands & techniques
├── Quick_Reference_Checklist.md # Daily checklists
├── tools/                      # Python security tools
│   ├── scanner.py              # Main scanner
│   ├── subdomain_discovery.py  # Subdomain enumeration
│   ├── endpoint_discovery.py   # API endpoint discovery
│   ├── js_analyzer.py          # JS analysis
│   ├── param_fuzzer.py         # Parameter fuzzing
│   ├── scope_validator.py      # Scope checking
│   ├── deep_scan.py            # Deep vulnerability scan
│   ├── false_positive_detector.py
│   ├── web_hacking_2025/       # Advanced scanner (11 techniques)
│   │   ├── run.py              # CLI entry point
│   │   ├── scanner.py          # Main module
│   │   └── [attack modules]    # Individual technique modules
│   └── requirements.txt
└── KingOfBugBountyTips/        # External tips (empty)
```

---

## Bug Bounty Program Rules

### Amazon VRP

**Scope:** `*.amazon` (all retail marketplaces) + mobile apps

**CRITICAL Requirements:**
```
User-Agent: amazonvrpresearcher_<h1username>
Rate Limit: 5 requests/second MAX
Email:      <h1username>@wearehackerone.com
```

**Out of Scope:**
- AWS subdomains (`aws` in domain)
- `.a2z` and `.dev` domains
- Test/QA/staging/preprod/gamma/beta environments

**High-Value Vulnerabilities:**
- Critical: RCE, SQLi, XXE, High-impact XSS
- High: SSRF, Auth Bypass, Privilege Escalation
- Medium: Directory Traversal, IDOR, CORS

**Not Eligible:**
- Clickjacking, Self-XSS, Email Spoofing
- Missing headers/cookie flags
- Login/logout CSRF, DOS/DDOS
- Scanner-only outputs

### Shopify BBP

**Registration:** https://partners.shopify.com/signup/bugbounty

**CRITICAL Requirements:**
```
Email:      <h1username>@wearehackerone.com
Testing:    ONLY stores you created
```

**Forbidden Actions:**
- Testing live merchant stores = DISQUALIFICATION
- Contacting Shopify Support = POTENTIAL BAN
- Public disclosure before resolution

**Bounty Calculation:**
- Score < 3 = $500
- Score >= 3 = Calculated amount
- Must demonstrate functional PoC with security impact

---

## Tools Usage

### Main Scanner (Web Hacking 2025)

```bash
cd tools

# List techniques
python -m web_hacking_2025.run --list-techniques

# Scan with program compliance
python -m web_hacking_2025.run target.amazon.com \
  --program amazon \
  --h1-user YOUR_USERNAME

# Specific techniques
python -m web_hacking_2025.run target.com \
  --techniques smuggling,cache,ssrf,xss

# Resume interrupted scan
python -m web_hacking_2025.run -f domains.txt --resume
```

**11 Available Techniques:**
1. `smuggling` - HTTP Request Smuggling
2. `cache` - Cache Poisoning
3. `auth` - Authentication Bypass
4. `xss` - XSS/CSRF/CORS
5. `parser` - XXE/Parser attacks
6. `inject` - SSTI/SQL/Command injection
7. `ssrf` - Server-Side Request Forgery
8. `xsleaks` - XS-Leaks
9. `framework` - Framework vulnerabilities
10. `deser` - Deserialization
11. `protocol` - Protocol attacks

### Other Tools

```bash
# Subdomain enumeration
python subdomain_discovery.py amazon.com

# Run general scan
python run_scan.py https://target.com

# Validate scope
python scope_validator.py "https://target.amazon.com"
```

---

## When Assisting with This Project

### DO:
- Check scope before suggesting any target
- Include User-Agent requirements in scan commands
- Respect rate limits (5 req/s for Amazon)
- Use `@wearehackerone.com` email format
- Reference Overview.md for program-specific rules
- Validate findings reduce false positives

### DON'T:
- Suggest testing AWS, .a2z, or .dev domains
- Recommend third-party XSS Hunter services
- Ignore program-specific testing restrictions
- Suggest testing Shopify stores not owned by user
- Recommend contacting support channels

### When Writing Code:
- Add User-Agent headers for Amazon scans
- Implement rate limiting (use `time.sleep()`)
- Include scope validation checks
- Handle false positives properly
- Follow existing code patterns in `tools/`

### When Reviewing Findings:
- Check if target is explicitly in-scope
- Verify vulnerability has security impact
- Ensure PoC is functional, not theoretical
- Match severity to program guidelines
- Flag any out-of-scope issues

---

## Common Tasks

### Add New Bug Bounty Program

1. Create directory: `<ProgramName>/`
2. Add `Overview.md` with full policy from HackerOne/Bugcrowd
3. Document: scope, out-of-scope, testing rules, severity levels
4. Update this file with program summary

### Prepare a Report

1. Verify target in-scope
2. Create working PoC
3. Write clear reproduction steps
4. Calculate severity per program guidelines
5. Include screenshots/video evidence

### Validate Scope

```bash
# Use scope validator
python tools/scope_validator.py "https://target.com"

# Or check manually:
# Amazon: No 'aws', '.a2z', '.dev', 'test', 'staging' in URL
# Shopify: Must be your own test store
```

---

## File References

| Topic | File | Key Lines |
|-------|------|-----------|
| Amazon scope | `Amazon/Overview.md` | Lines 1-50 |
| Amazon testing rules | `Amazon/Overview.md` | Lines 121-133 |
| Amazon severity | `Amazon/Overview.md` | Lines 182-202 |
| Amazon GenAI rules | `Amazon/Overview.md` | Lines 206-241 |
| Shopify requirements | `Shopify/Overview.md` | Lines 24-32 |
| Shopify bounty calc | `Shopify/Overview.md` | Lines 41-44 |
| Testing strategy | `Testing_Strategy.md` | Full document |
| Recon commands | `Reconnaissance_Guide.md` | Full document |
| Daily checklist | `Quick_Reference_Checklist.md` | Full document |
| Scanner docs | `tools/web_hacking_2025/README.md` | Full document |

---

## Important Reminders

1. **Always verify scope** before testing any target
2. **Rate limits are mandatory** - violations may result in ban
3. **Self-host testing infrastructure** - no third-party services for Amazon
4. **Test only owned stores** for Shopify
5. **Document everything** - screenshots, videos, timestamps
6. **Report responsibly** - follow program disclosure rules
