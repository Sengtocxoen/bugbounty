# Web Hacking Techniques 2025 Scanner

A comprehensive vulnerability scanner based on [PortSwigger's Top 10 Web Hacking Techniques of 2025 nominations](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open).

## Features

- **11 Technique Categories** covering all major 2025 web attack vectors
- **Bug Bounty Compliance** - Automatic User-Agent, rate limiting, scope validation
- **Progress Persistence** - Scans can be interrupted and resumed
- **Real-time Output** - Findings saved immediately to prevent data loss
- **Severity Classification** - Critical/High/Medium/Low/Info categorization

## Installation

```bash
cd /path/to/bugbounty/tools
pip install requests
```

## Quick Start

```bash
# Scan a single domain with ALL 11 techniques
python -m web_hacking_2025.run example.com

# Scan multiple domains from file
python -m web_hacking_2025.run -f domains.txt

# Resume interrupted scan
python -m web_hacking_2025.run -f domains.txt --resume

# Run specific techniques only
python -m web_hacking_2025.run example.com --techniques smuggling,cache,xss,ssrf

# Bug bounty mode (Amazon VRP)
python -m web_hacking_2025.run example.amazon.com --program amazon --h1-user myh1username

# Bug bounty mode (Shopify)
python -m web_hacking_2025.run test.myshopify.com --program shopify --h1-user myh1username
```

## Techniques (11 Categories)

### 1. HTTP Request Smuggling (`smuggling`)
- CL.TE / TE.CL / TE.TE desync attacks
- Transfer-Encoding obfuscation (Funky Chunks)
- HTTP/2 to HTTP/1.1 downgrade
- H2C smuggling potential

### 2. Cache Poisoning (`cache`)
- Unkeyed header poisoning
- Web cache deception
- Path normalization issues
- Stale-while-revalidate exploitation
- Vary header bypass

### 3. Authentication Bypass (`auth`)
- OAuth redirect_uri manipulation
- SAML endpoint discovery
- Path-based auth bypass
- Header-based bypass (X-Original-URL, etc.)
- IDOR pattern detection
- JWT vulnerability indicators

### 4. Cross-Site Attacks (`xss`)
- Reflected XSS detection
- DOM clobbering indicators
- CSRF protection analysis
- Clickjacking protection check
- CORS misconfiguration
- GraphQL CSRF (CSWSH)
- Open redirect

### 5. Parser/XXE (`parser`)
- XXE (XML External Entity) variants
- SVG XXE
- JSON parser differentials (Go case sensitivity)
- URL parser confusion
- Content-type polyglots
- Path traversal via encoding

### 6. SSTI/Injection (`inject`)
- Server-Side Template Injection (Jinja2, Freemarker, etc.)
- SQL injection (error/time-based)
- Command injection
- PDF generation exploits
- Prototype pollution

### 7. SSRF (`ssrf`)
- Cloud metadata access (AWS, GCP, Azure, etc.)
- Internal network scanning
- Protocol wrapper abuse (file://, gopher://, dict://)
- SSRF filter bypass techniques
- Blind SSRF indicators

### 8. XS-Leaks (`xsleaks`)
- ETag length variation detection
- Response timing oracles
- Content-length variation
- Error-based state detection
- Frame counting potential
- Search oracles

### 9. Framework Vulnerabilities (`framework`)
- ASP.NET (ViewState, path traversal)
- Java/Spring (actuator exposure, Spring4Shell indicators)
- PHP (phpinfo, type juggling)
- Node.js (package.json, prototype pollution)
- Rails (mass assignment)
- ORM injection (Prisma, Sequelize, etc.)

### 10. Deserialization (`deser`)
- Java deserialization indicators
- .NET ViewState tampering
- PHP unserialize()
- phar:// wrapper abuse
- Python pickle
- Node.js serialize

### 11. Protocol Attacks (`protocol`)
- WebSocket CSWSH
- GraphQL introspection & injection
- HTTP/2 support detection
- gRPC endpoint discovery
- Server-Sent Events
- CORS for APIs

## Bug Bounty Program Support

### Amazon VRP
```bash
python -m web_hacking_2025.run example.amazon.com --program amazon --h1-user myusername
```
- User-Agent: `amazonvrpresearcher_myusername`
- Rate limit: 5 req/s (max allowed)
- Scope validation available with `--validate-scope`

### Shopify
```bash
python -m web_hacking_2025.run test.myshopify.com --program shopify --h1-user myusername
```

### Show Program Rules
```bash
python -m web_hacking_2025.run --program amazon --show-rules
```

## Output Structure

```
web_hacking_2025_results/
├── scan_progress.json      # Full scan state (for resume)
├── domains_status.txt      # Quick status overview
└── findings/
    ├── critical_findings.json
    ├── high_findings.json
    ├── medium_findings.json
    ├── low_findings.json
    ├── info_findings.json
    └── all_findings.txt    # Human-readable report
```

## Programmatic Usage

```python
from web_hacking_2025 import WebHackingScanner

# Initialize scanner
scanner = WebHackingScanner(
    output_dir="./results",
    rate_limit=5.0,
    techniques=["smuggling", "cache", "xss", "ssrf"],
    verbose=True
)

# Run scan
findings = scanner.run(["example.com", "test.example.com"])

# Process findings
for finding in findings:
    if finding.severity == "critical":
        print(f"CRITICAL: {finding.title}")
```

### Using Individual Scanners

```python
from web_hacking_2025 import (
    HTTPSmuggling,
    SSRFDetection,
    ScanProgress
)

# Initialize
progress = ScanProgress(output_dir="./results")
progress.add_domain("example.com", ["smuggling", "ssrf"])

# Run specific scanners
smuggling_scanner = HTTPSmuggling(rate_limit=5.0, verbose=True)
findings = smuggling_scanner.scan("example.com", progress)

ssrf_scanner = SSRFDetection(rate_limit=5.0, verbose=True)
ssrf_findings = ssrf_scanner.scan("example.com", progress)
```

### Bug Bounty Config

```python
from web_hacking_2025 import get_program_config, ScopeValidator

# Get Amazon VRP config
config = get_program_config("amazon")
user_agent = config.get_user_agent("myh1user")
email = config.get_email("myh1user")

# Validate scope
validator = ScopeValidator(config)
if validator.is_valid("example.amazon.com"):
    print("Domain is in scope")
```

## Command Line Options

```
usage: run.py [-h] [-f FILE] [-o OUTPUT] [--techniques TECHNIQUES]
              [--rate RATE] [--user-agent USER_AGENT] [--resume]
              [--threads THREADS] [-q] [--list-techniques]
              [--program {amazon,shopify,generic}] [--h1-user H1_USER]
              [--validate-scope] [--show-rules]
              [domain]

Options:
  domain                Target domain
  -f, --file            File containing domains (one per line)
  -o, --output          Output directory (default: ./web_hacking_2025_results)
  --techniques          Comma-separated techniques to run
  --rate                Requests per second (auto-set by --program)
  --user-agent          Custom User-Agent (auto-set by --program)
  --resume              Resume previous scan
  --threads             Parallel threads (default: 3)
  -q, --quiet           Reduce output verbosity
  --list-techniques     List available techniques
  --program             Bug bounty program (amazon, shopify, generic)
  --h1-user             HackerOne username for program compliance
  --validate-scope      Validate domains against program scope
  --show-rules          Show program rules and exit
```

## Safety Notes

1. **Only test authorized targets** - Ensure you have permission
2. **Use appropriate rate limits** - Respects program limits automatically
3. **Non-destructive payloads** - Scanner uses detection-only probes
4. **Review findings manually** - Automated detection needs verification
5. **Follow program rules** - Use `--show-rules` to review requirements

## References

- [PortSwigger Top 10 Web Hacking Techniques 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open)
- HTTP Request Smuggling research
- Web Cache Poisoning techniques
- SAML/OAuth vulnerability research
- XS-Leaks Wiki
- Server-Side Template Injection
- Cloud Metadata exploitation
