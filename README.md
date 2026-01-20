# Bug Bounty Automation Suite

A comprehensive suite of tools and scripts for bug bounty hunting and security testing.

## Features

- Automated vulnerability scanning
- Subdomain enumeration
- Web path discovery
- SQL injection testing
- XSS detection
- API endpoint discovery
- Beautiful HTML reports with dark mode support

## Bug Bounty Workflows

### 1. Initial Reconnaissance
```bash
# Run comprehensive reconnaissance
python automation/bugbounty_scanner.py -t example.com --category recon
```
- Subdomain enumeration using multiple tools
- DNS records analysis
- Cloud infrastructure detection
- Technology stack identification
- Historical data gathering

### 2. Content Discovery
```bash
# Run web content discovery
python automation/bugbounty_scanner.py -t example.com --category web_scan
```
- Directory and file enumeration
- API endpoint discovery
- JavaScript file analysis
- Backup file detection
- Configuration file discovery

### 3. Vulnerability Assessment
```bash
# Run vulnerability scanning
python automation/bugbounty_scanner.py -t example.com --category vuln_scan
```
- XSS vulnerability testing
- SQL injection detection
- Authentication bypass attempts
- Business logic testing
- API security testing

### 4. Advanced Testing Workflows

#### API Testing Workflow
```bash
# Run API-focused scan
python automation/bugbounty_scanner.py -t api.example.com --config api_config.yaml
```
- API endpoint discovery
- Authentication testing
- Rate limiting analysis
- Parameter fuzzing
- Response analysis

#### Authentication Testing Workflow
```bash
# Run authentication testing
python automation/bugbounty_scanner.py -t example.com --config auth_config.yaml
```
- Login form testing
- Password reset functionality
- Session management
- OAuth implementation
- 2FA bypass attempts

#### Business Logic Testing Workflow
```bash
# Run business logic testing
python automation/bugbounty_scanner.py -t example.com --config logic_config.yaml
```
- Workflow testing
- State management
- Race conditions
- Price manipulation
- Access control testing

### 5. Common Bug Bounty Methodologies

#### Information Gathering
1. **Passive Reconnaissance**
   - DNS records
   - SSL certificates
   - WHOIS information
   - Historical data
   - Technology stack

2. **Active Reconnaissance**
   - Subdomain enumeration
   - Port scanning
   - Service identification
   - Cloud infrastructure
   - Network mapping

#### Vulnerability Discovery
1. **Web Application Testing**
   - Input validation
   - Authentication mechanisms
   - Session management
   - Access controls
   - Business logic

2. **API Testing**
   - Endpoint discovery
   - Authentication
   - Rate limiting
   - Input validation
   - Response analysis

3. **Mobile Application Testing**
   - API endpoints
   - Authentication
   - Data storage
   - Network traffic
   - Binary analysis

#### Exploitation Techniques
1. **XSS Testing**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS
   - WAF bypass techniques
   - Event handler injection

2. **SQL Injection**
   - Error-based
   - Blind injection
   - Time-based
   - Union-based
   - WAF bypass techniques

3. **Authentication Bypass**
   - Session manipulation
   - Token analysis
   - 2FA bypass
   - Password reset
   - OAuth vulnerabilities

### 6. Best Practices

1. **Scope Understanding**
   - Read program rules
   - Understand boundaries
   - Identify critical assets
   - Document findings
   - Follow responsible disclosure

2. **Testing Methodology**
   - Start with reconnaissance
   - Map application structure
   - Identify entry points
   - Test systematically
   - Document all steps

3. **Report Writing**
   - Clear vulnerability description
   - Step-by-step reproduction
   - Impact assessment
   - Remediation suggestions
   - Proof of concept

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/bugbounty.git
cd bugbounty
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Unix/macOS
venv\Scripts\activate     # On Windows
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Install required tools:
```bash
python tools/tools_manager.py --install
```

## Available Tools

The suite includes the following tools:

### Python Tools
- **Sublist3r**: Subdomain enumeration tool using multiple sources
- **Dirsearch**: Fast web path scanner with multiple wordlists
- **SQLMap**: Advanced SQL injection testing tool
- **Knock**: Subdomain enumeration tool with multiple sources
- **MassDNS**: High-performance DNS stub resolver
- **ASNLookup**: ASN lookup tool for finding IP ranges
- **SecLists**: Collection of multiple types of lists for security testing
- **BBOT**: Recursive internet scanner with advanced OSINT capabilities and modular scanning

### Go Tools
- **Httprobe**: HTTP probe tool for finding live hosts
- **Waybackurls**: Wayback machine URL finder
- **Aquatone**: Visual recon tool for web applications
- **Katana**: Next-generation crawling and spidering framework for web application security testing

## Usage

### Unified One-Command Runner

Run the full pipeline (deep scan + web_hacking_2025 techniques) from a single script:

```bash
# Full run on a single target
python tools/run_all.py example.com -p amazon -u myh1user

# Run from a file of targets
python tools/run_all.py -f targets.txt -p shopify -u myh1user

# Use discovered subdomains for technique scanning
python tools/run_all.py example.com --scan-discovered

# Skip deep scan (run only web_hacking_2025)
python tools/run_all.py example.com --skip-deep
```

Outputs are saved under `./combined_results/deep_scan` and `./combined_results/web_hacking_2025`.

### Running the Scanner

1. For a single target:
```bash
python automation/bugbounty_scanner.py -t https://example.com
```

2. For multiple targets from a CSV file:
```bash
python automation/bugbounty_scanner.py -c targets.csv
```

3. With custom configuration:
```bash
python automation/bugbounty_scanner.py -t https://example.com -f config.yaml
```

4. Run specific scan categories:
```bash
# Run only reconnaissance
python automation/bugbounty_scanner.py -t example.com --category recon

# Run only web scanning
python automation/bugbounty_scanner.py -t example.com --category web_scan

# Run only vulnerability scanning
python automation/bugbounty_scanner.py -t example.com --category vuln_scan
```

### Using Individual Tools

You can use the tools manager to run individual tools:

1. List available tools:
```bash
python tools/tools_manager.py --list
```

2. Run a specific tool:
```bash
python tools/tools_manager.py --tool sublist3r --args -d example.com
```

## CSV Target Format

The CSV file should have the following columns:
- `identifier`: The target URL or domain
- `asset_type`: Type of asset (url/domain)
- `instruction`: Any specific instructions for scanning
- `eligible_for_bounty`: Whether the target is eligible for bounty (true/false)
- `max_severity`: Maximum severity level to report (low/medium/high/critical)

Example:
```csv
identifier,asset_type,instruction,eligible_for_bounty,max_severity
https://example.com,url,Scan all endpoints,true,high
example.com,domain,Focus on API endpoints,true,medium
```

## Configuration

You can customize the scanner's behavior using a YAML configuration file:

```yaml
scan_categories:
  recon:
    enabled: true
    tools: ['sublist3r', 'knock', 'massdns', 'asnlookup', 'bbot']
    settings:
      max_concurrent_requests: 5
      request_timeout: 5
  
  web_scan:
    enabled: true
    tools: ['dirsearch', 'katana']
    settings:
      max_depth: 3
      concurrency: 10
  
  vuln_scan:
    enabled: true
    tools: ['sqlmap', 'xsscrapy']
    settings:
      max_severity: 'high'
      scan_timeout: 300

endpoints:
  - /api/v1/
  - /api/v2/
  - /auth/
  - /login
  - /register
  - /reset-password
  - /profile
  - /settings
  - /admin/
  - /upload/
  - /download/
  - /export/
  - /import/

auth_endpoints:
  - /login
  - /register
  - /reset-password
  - /oauth/authorize
  - /oauth/token

settings:
  max_concurrent_requests: 5
  request_timeout: 5
  retry_attempts: 3
  follow_redirects: true
  max_workers: 10
  shodan_api_key: ''  # Add your Shodan API key here
  censys_api_id: ''   # Add your Censys API ID here
  censys_api_secret: '' # Add your Censys API secret here
```

## Reports

The scanner generates comprehensive HTML reports with the following features:
- Dark mode support
- Responsive design
- Detailed findings from all tools
- Severity-based categorization
- Interactive elements
- Exportable results

Reports are saved in the `scan_results_YYYYMMDD_HHMMSS` directory.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any target.
