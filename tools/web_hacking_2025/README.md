# Web Hacking Techniques 2025 Scanner

A comprehensive vulnerability scanner based on [PortSwigger's Top 10 Web Hacking Techniques of 2025 nominations](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open).

## Features

- **6 Technique Categories** covering the latest web attack vectors
- **Progress Persistence** - Scans can be interrupted and resumed
- **Real-time Output** - Findings saved immediately to prevent data loss
- **Severity Classification** - Findings categorized by impact
- **Rate Limiting** - Configurable to respect target policies
- **Modular Design** - Run specific techniques or all at once

## Installation

```bash
cd /path/to/bugbounty/tools
pip install requests
```

## Quick Start

```bash
# Scan a single domain with all techniques
python -m web_hacking_2025.run example.com

# Scan multiple domains from file
python -m web_hacking_2025.run -f domains.txt

# Resume interrupted scan
python -m web_hacking_2025.run -f domains.txt --resume

# Run specific techniques only
python -m web_hacking_2025.run example.com --techniques smuggling,cache,xss

# Custom rate limit and output
python -m web_hacking_2025.run example.com --rate 3 -o ./my_results
```

## Techniques

### 1. HTTP Request Smuggling (`smuggling`)
- CL.TE / TE.CL desync attacks
- Transfer-Encoding obfuscation
- HTTP/2 to HTTP/1.1 downgrade
- Chunked encoding quirks (Funky Chunks)

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
- JSON parser differentials
- URL parser confusion
- Content-type confusion
- Path traversal via encoding

### 6. SSTI/Injection (`inject`)
- Server-Side Template Injection
- SQL injection (error/time-based)
- Command injection
- PDF generation exploits
- Prototype pollution

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
    techniques=["smuggling", "cache", "xss"],
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
    CachePoisoning,
    ScanProgress
)

# Initialize
progress = ScanProgress(output_dir="./results")
progress.add_domain("example.com", ["smuggling"])

# Run specific scanner
smuggling_scanner = HTTPSmuggling(rate_limit=5.0, verbose=True)
findings = smuggling_scanner.scan("example.com", progress)
```

## Command Line Options

```
usage: run.py [-h] [-f FILE] [-o OUTPUT] [--techniques TECHNIQUES]
              [--rate RATE] [--user-agent USER_AGENT] [--resume]
              [--threads THREADS] [-q] [--list-techniques]
              [domain]

Options:
  domain              Target domain
  -f, --file          File containing domains (one per line)
  -o, --output        Output directory (default: ./web_hacking_2025_results)
  --techniques        Comma-separated techniques to run
  --rate              Requests per second (default: 5)
  --user-agent        Custom User-Agent string
  --resume            Resume previous scan
  --threads           Parallel threads (default: 3)
  -q, --quiet         Reduce output verbosity
  --list-techniques   List available techniques
```

## Safety Notes

1. **Only test authorized targets** - Ensure you have permission
2. **Use appropriate rate limits** - Default 5 req/s, adjust as needed
3. **Non-destructive payloads** - Scanner uses detection-only probes
4. **Review findings manually** - Automated detection needs verification

## References

- [PortSwigger Top 10 Web Hacking Techniques 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025-nominations-open)
- HTTP Request Smuggling research
- Web Cache Poisoning techniques
- SAML/OAuth vulnerability research
- Server-Side Template Injection
