# Bug Bounty Workspace

A comprehensive workspace for security researchers participating in bug bounty programs. This repository contains tools, documentation, and program-specific guidelines for ethical vulnerability research.

## Project Structure

```
bugbounty/
├── README.md                      # This file - project overview
├── CLAUDE.md                      # Instructions for Claude AI assistant
├── Gemini.md                      # Instructions for Gemini AI assistant
│
├── docs/                          # Documentation (guides & references)
│   ├── Testing_Strategy.md        # Strategic testing approaches
│   ├── Reconnaissance_Guide.md    # Target discovery techniques
│   └── Quick_Reference_Checklist.md # Checklists for daily use
│
├── programs/                      # Bug bounty program policies
│   ├── Amazon/
│   │   └── Overview.md            # Amazon VRP policy & scope
│   └── Shopify/
│       └── Overview.md            # Shopify BBP policy & scope
│
├── tools/                         # Security testing tools
│   ├── scanner.py                 # Main vulnerability scanner
│   ├── subdomain_discovery.py     # Subdomain enumeration
│   ├── enhanced_subdomain_scanner.py
│   ├── endpoint_discovery.py      # API endpoint discovery
│   ├── js_analyzer.py             # JavaScript analysis
│   ├── param_fuzzer.py            # Parameter fuzzing
│   ├── scope_validator.py         # Scope validation utility
│   ├── tech_detection.py          # Technology stack detection
│   ├── bug_discovery.py           # Automated bug detection
│   ├── deep_scan.py               # Deep vulnerability scanning
│   ├── false_positive_detector.py # Reduce false positives
│   ├── config.py                  # Configuration settings
│   ├── run_scan.py                # Scan runner script
│   ├── run_subdomain_scan.py      # Subdomain scan runner
│   └── web_hacking_2025/          # Advanced scanner module
│       ├── README.md              # Module documentation
│       ├── scanner.py             # Main scanner
│       ├── run.py                 # CLI runner
│       └── [technique modules]    # Individual attack modules
│
├── resources/                     # External resources & tips
│   └── KingOfBugBountyTips/       # Community tips collection
│
└── results/                       # Scan output directory (gitignored)
```

> **Note:** Current structure differs slightly. See "Recommended Reorganization" below.

---

## Quick Start

### 1. Setup Environment

```bash
# Clone the repository
git clone <repository-url>
cd bugbounty

# Install Python dependencies
cd tools
pip install -r requirements.txt
```

### 2. Configure for Your Bug Bounty Program

Before testing, update your HackerOne username in the tools:

```bash
# For Amazon VRP
python -m web_hacking_2025.run target.amazon.com --program amazon --h1-user YOUR_H1_USERNAME

# For Shopify
python -m web_hacking_2025.run your-store.myshopify.com --program shopify --h1-user YOUR_H1_USERNAME
```

### 3. Run a Scan

```bash
cd tools

# Basic scan
python run_scan.py https://target.com

# Advanced scan with 2025 techniques
python -m web_hacking_2025.run target.com

# Subdomain enumeration
python run_subdomain_scan.py amazon.com
```

---

## Documentation

| File | Description |
|------|-------------|
| [Testing_Strategy.md](Testing_Strategy.md) | Comprehensive testing strategies for Amazon & Shopify |
| [Reconnaissance_Guide.md](Reconnaissance_Guide.md) | Step-by-step recon commands and techniques |
| [Quick_Reference_Checklist.md](Quick_Reference_Checklist.md) | Daily checklists and quick references |

---

## Bug Bounty Programs

### Amazon VRP

**Scope:** `*.amazon` (all retail marketplaces)

**Key Requirements:**
- User-Agent: `amazonvrpresearcher_<your_h1_username>`
- Rate Limit: MAX 5 requests/second
- Email: `<your_h1_username>@wearehackerone.com`
- NO third-party testing services (self-host only)

**Out of Scope:**
- AWS subdomains, `.a2z`, `.dev` domains
- Test/staging/QA environments

See: [Amazon/Overview.md](Amazon/Overview.md)

### Shopify Bug Bounty

**Scope:** Shopify platform, partner portal, APIs

**Key Requirements:**
- Test ONLY stores you created
- Register at: https://partners.shopify.com/signup/bugbounty
- Email: `<your_h1_username>@wearehackerone.com`
- NEVER contact Shopify Support about testing

See: [Shopify/Overview.md](Shopify/Overview.md)

---

## Tools Overview

### Core Scanners

| Tool | Purpose |
|------|---------|
| `scanner.py` | Main vulnerability scanner |
| `deep_scan.py` | Thorough vulnerability analysis |
| `web_hacking_2025/` | PortSwigger Top 10 2025 techniques |

### Reconnaissance

| Tool | Purpose |
|------|---------|
| `subdomain_discovery.py` | Find subdomains |
| `enhanced_subdomain_scanner.py` | Advanced subdomain enum |
| `endpoint_discovery.py` | API endpoint mapping |
| `js_analyzer.py` | JavaScript secrets & endpoints |
| `tech_detection.py` | Technology stack fingerprinting |

### Utilities

| Tool | Purpose |
|------|---------|
| `scope_validator.py` | Check if target is in scope |
| `param_fuzzer.py` | Parameter tampering tests |
| `false_positive_detector.py` | Filter out false positives |

### Web Hacking 2025 Module

Advanced scanner based on PortSwigger's Top 10 Web Hacking Techniques 2025:

```bash
# List available techniques
python -m web_hacking_2025.run --list-techniques

# Run specific techniques
python -m web_hacking_2025.run target.com --techniques smuggling,cache,ssrf

# Resume interrupted scan
python -m web_hacking_2025.run -f domains.txt --resume
```

Techniques: HTTP Smuggling, Cache Poisoning, Auth Bypass, XSS/CSRF, XXE/Parser, SSTI/Injection, SSRF, XS-Leaks, Framework Vulns, Deserialization, Protocol Attacks

See: [tools/web_hacking_2025/README.md](tools/web_hacking_2025/README.md)

---

## Working with AI Assistants

This project includes configuration files for AI coding assistants:

| File | AI Assistant | Purpose |
|------|--------------|---------|
| `CLAUDE.md` | Claude (Anthropic) | Project context & guidelines |
| `Gemini.md` | Gemini (Google) | Project context & guidelines |

### How to Update AI Instructions

1. **CLAUDE.md** - Claude Code reads this automatically when working in the repo
2. **Gemini.md** - Reference this file when working with Gemini

These files help AI assistants understand:
- Project structure and purpose
- Bug bounty program rules
- Testing restrictions and requirements
- Code organization guidelines

---

## Workflow

### Daily Testing Routine

1. **Morning Setup (15 min)**
   - Check program updates on HackerOne
   - Review scope changes
   - Plan focus area

2. **Testing Session**
   ```bash
   # 1. Validate scope
   python tools/scope_validator.py "https://target.amazon.com"

   # 2. Run reconnaissance
   python tools/subdomain_discovery.py amazon.com

   # 3. Scan for vulnerabilities
   python -m web_hacking_2025.run target.amazon.com --program amazon --h1-user YOUR_USERNAME
   ```

3. **Documentation**
   - Record all findings immediately
   - Take screenshots/videos
   - Prepare PoC before reporting

### Report Preparation

1. Verify target is in-scope
2. Create working Proof of Concept
3. Document clear reproduction steps
4. Calculate severity (use program guidelines)
5. Submit via HackerOne

---

## Recommended Reorganization

Current file locations vs. suggested structure:

| Current Location | Suggested Location | Reason |
|-----------------|-------------------|--------|
| `Testing_Strategy.md` | `docs/Testing_Strategy.md` | Group documentation |
| `Reconnaissance_Guide.md` | `docs/Reconnaissance_Guide.md` | Group documentation |
| `Quick_Reference_Checklist.md` | `docs/Quick_Reference_Checklist.md` | Group documentation |
| `Amazon/` | `programs/Amazon/` | Clarify purpose |
| `Shopify/` | `programs/Shopify/` | Clarify purpose |
| `KingOfBugBountyTips/` | `resources/KingOfBugBountyTips/` | External resources |

To reorganize:

```bash
# Create new directories
mkdir -p docs programs resources

# Move documentation
mv Testing_Strategy.md docs/
mv Reconnaissance_Guide.md docs/
mv Quick_Reference_Checklist.md docs/

# Move programs
mv Amazon programs/
mv Shopify programs/

# Move resources
mv KingOfBugBountyTips resources/

# Update CLAUDE.md paths accordingly
```

---

## Safety & Ethics

**Always:**
- Test only explicitly in-scope assets
- Follow program rate limits
- Use authorized test accounts
- Report vulnerabilities responsibly
- Self-host blind testing infrastructure

**Never:**
- Access other users' data
- Test production systems without permission
- Exceed allowed request rates
- Use third-party data collection services
- Post-exploit beyond PoC requirements

---

## Contributing

When adding new programs or tools:

1. **New Program:** Create `programs/<ProgramName>/Overview.md` with full policy
2. **New Tool:** Add to `tools/` with proper documentation
3. **Documentation:** Update relevant guides in `docs/`
4. **AI Context:** Update `CLAUDE.md` and `Gemini.md` as needed

---

## License

This workspace is for personal bug bounty research. Tools and documentation are provided as-is for educational purposes.

---

## Useful Links

- [HackerOne](https://hackerone.com)
- [Amazon VRP Program](https://hackerone.com/amazonvrp)
- [Shopify Bug Bounty](https://hackerone.com/shopify)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
