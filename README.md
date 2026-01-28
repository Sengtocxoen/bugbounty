# Bug Bounty Scanner

A comprehensive, configuration-based vulnerability scanner for bug bounty programs.

## 🚀 Quick Start

1. **Edit Configuration**
   ```bash
   notepad scan_config.yaml
   ```

2. **Set Your Settings**
   ```yaml
   program: "anduril"              # Program name
   h1_username: "your_username"    # Your HackerOne username
   
   targets:
     - "example.com"               # Add your targets
   
   custom_headers:
     X-HackerOne-Research: "your_username"  # Required headers
   ```

3. **Run Scanner**
   ```bash
   python config_scanner.py scan_config.yaml
   ```

4. **Review & Confirm**
   - Scanner shows complete configuration review
   - Confirm to start, or cancel if something's wrong

## 📁 Structure

```
bugbounty/
├── config_scanner.py          # Main scanner (runs from config file)
├── scan_config.yaml           # YOUR CONFIGURATION FILE
├── scanner.py                 # Direct scanner (command-line)
├── requirements.txt           # Dependencies
├── tools/                     # Scanner modules
│   ├── discovery/             # Subdomain & endpoint discovery
│   ├── analysis/              # Tech detection, JS analysis, fuzzing
│   ├── verification/          # Vulnerability verification
│   └── utils/                 # Config & utilities
└── docs/                      # Documentation
```

## ⚙️ Configuration

Edit `scan_config.yaml` to set:

- **Program**: `amazon`, `shopify`, `anduril`, or leave empty
- **Targets**: List of domains to scan
- **Custom Headers**: Add required HTTP headers
- **Phases**: Enable/disable scan phases
- **Rate Limiting**: Requests per second
- **Verification**: Auto-verify findings
- **Output**: Where to save results

## 🎯 Scan Phases

1. **Subdomain Discovery** - Find subdomains (8+ sources)
2. **Port Scanning** - Scan common ports
3. **Endpoint Discovery** - Find URLs & endpoints
4. **Technology Detection** - Fingerprint technologies
5. **JavaScript Analysis** - Extract secrets & APIs
6. **Parameter Fuzzing** - Test for vulnerabilities
7. **Vulnerability Verification** - Confirm findings

## 📋 Supported Programs

- **Amazon VRP** - Auto-configured with required User-Agent
- **Shopify** - Bug bounty program settings
- **Anduril Industries** - Required X-HackerOne-Research header
- **Generic** - Works with any program

## 💡 Examples

### Quick Recon
```yaml
phases:
  subdomain_discovery: true
  port_scanning: true
  verification: false
```

### Full Deep Scan
```yaml
phases:
  subdomain_discovery: true
  port_scanning: true
  endpoint_discovery: true
  tech_detection: true
  js_analysis: true
  param_fuzzing: true
  verification: true
```

### Verification Only
```yaml
phases:
  subdomain_discovery: false
  # ... all false except:
  verification: true
```

## 🛠️ Installation

```bash
pip install -r requirements.txt
```

## 📚 Documentation

- `docs/CONFIG_QUICKSTART.md` - Quick start guide
- `docs/CONFIG_TEMPLATES.md` - Configuration templates
- `tools/verification/README.md` - Verification system docs

## 🔧 Command Line (Alternative)

You can also use direct command-line mode:

```bash
python scanner.py deep -t example.com --program anduril --username yourh1user
```

But configuration file mode is recommended for easier use.

## ⚠️ Safety

- **Always review** configuration before running
- **Respect rate limits** set by programs
- **Test on authorized targets** only
- **No data exfiltration** - read-only verification
- **Follow program rules** - check HackerOne program page

## 📝 License

For bug bounty research only. Use responsibly.
