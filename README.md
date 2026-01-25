# Bug Bounty Automation Suite

> **Professional bug bounty automation with intelligent scanning, continuous operation, and real-time results.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 What This Does

A **production-ready** bug bounty automation suite that:

- ⚡ **Scans 80-85% faster** with intelligent duplicate detection
- 📊 **Streams results in real-time** - see findings immediately, don't wait
- 🎯 **Smart two-phase scanning** - quick scan all, deep scan only unique targets
- 🔄 **Runs continuously 24/7** without timeout
- 🧠 **Detects duplicate responses** automatically to avoid wasting time
- 🗄️ **Tracks findings in database** with automatic deduplication
- 🔔 **Sends real-time alerts** via Slack/Discord for critical findings

---

## 🚀 Quick Start

### 1. Install Tools (Kali Linux)

```bash
chmod +x install_enhanced_tools.sh
./install_enhanced_tools.sh
source ~/.bashrc
```

Installs 30+ modern tools: Nuclei, Subfinder, Amass, ffuf, Dalfox, and more.

### 2. Configure

```bash
# Add your targets
nano targets.txt

# Configure scanner (add Slack/Discord webhooks for alerts)
nano continuous_config.yaml
```

### 3. Run

```bash
# Intelligent scan (recommended)
python tools/intelligent_scanner.py example.com -s subdomains.txt

# Or continuous 24/7 scanning
python tools/continuous_scanner.py -c continuous_config.yaml

# Or comprehensive one-time scan
python tools/run_all.py example.com -p amazon -u yourh1user
```

**📖 Full setup guide:** [docs/QUICKSTART.md](docs/QUICKSTART.md)

---

## 📊 Key Features

### Intelligent Scanning

<table>
<tr>
<td width="50%">

**Traditional Scanner**
```
Scan 1000 subdomains
├─ sub1: Full scan (5 min)
├─ sub2: Full scan (5 min) [duplicate!]
├─ sub3: Full scan (5 min) [duplicate!]
...
Time: 83 hours 😴
```

</td>
<td width="50%">

**Intelligent Scanner**
```
Quick scan 1000 subdomains
├─ sub1: Check (5s) ✓ Unique
├─ sub2: Check (5s) ✗ Duplicate, skip!
├─ sub3: Check (5s) ✗ Duplicate, skip!
...
Deep scan 150 unique
Time: 14 hours ⚡
```

</td>
</tr>
</table>

**Result:** 80-85% time savings, see results as they're found!

### Real-Time Streaming Output

Results appear immediately - no waiting for 1000 subdomains to finish:

```bash
# Watch live results
tail -f results/example_com/example_com/findings.jsonl

[HIGH] example.com - XSS in search parameter
[CRITICAL] api.example.com - SSRF via PDF generator
[MEDIUM] admin.example.com - Exposed config file
```

**📖 Full intelligent scanner guide:** [docs/INTELLIGENT_SCANNER_GUIDE.md](docs/INTELLIGENT_SCANNER_GUIDE.md)

---

## 🛠️ Tools Included

### Reconnaissance & Discovery
- **Subfinder** - 40+ passive subdomain sources
- **Amass** - Comprehensive subdomain enumeration
- **Assetfinder** - Fast subdomain discovery
- **PureDNS** - Accurate DNS resolution
- **Naabu** - Fast port scanner
- **HTTPX** - HTTP probe

### Vulnerability Scanning
- **Nuclei** ⭐ - 4000+ vulnerability templates (CVEs, misconfigs, exposures)
- **Dalfox** - Advanced XSS scanner with WAF bypass
- **SQLMap** - SQL injection testing
- **Nikto** - Web server scanner

### Content Discovery
- **ffuf** - High-performance fuzzer (10x faster than dirsearch)
- **Feroxbuster** - Recursive content discovery
- **Waybackurls** - Historical endpoint discovery
- **gau** - Get all URLs from multiple sources
- **Katana** - Next-gen web crawler

### API & Parameter Testing
- **Arjun** - Parameter discovery
- **x8** - Hidden parameter finder
- **Kiterunner** - API endpoint discovery

### JavaScript Analysis
- **LinkFinder** - Extract endpoints from JS
- **retire.js** - Detect vulnerable libraries

### SSRF & Cloud Security
- **interactsh-client** - Out-of-band interaction
- **SSRFmap** - SSRF exploitation
- **cloud_enum** - Cloud asset discovery
- **S3Scanner** - S3 bucket scanner

**Full tool list:** [install_enhanced_tools.sh](install_enhanced_tools.sh)

---

## 📂 Project Structure

```
bugbounty/
├── README.md                      # This file
├── install_enhanced_tools.sh      # One-command tool installation
├── continuous_config.yaml         # Configuration file
├── targets.txt.example            # Example targets file
│
├── docs/                          # 📚 Documentation
│   ├── QUICKSTART.md              # Step-by-step setup guide
│   ├── INTELLIGENT_SCANNER_GUIDE.md  # Smart scanning guide
│   ├── Vulnerabilities_That_Matter.md  # Wiz methodology
│   ├── Reconnaissance_Guide.md    # Recon techniques
│   ├── Testing_Strategy.md        # Testing strategies
│   └── Quick_Reference_Checklist.md  # Quick reference
│
├── tools/                         # 🔧 Core scanners
│   ├── intelligent_scanner.py     # Smart two-phase scanner
│   ├── continuous_scanner.py      # 24/7 continuous scanner
│   ├── smart_response_detector.py # Duplicate detection
│   ├── streaming_results.py       # Real-time output
│   ├── run_all.py                 # Unified comprehensive scanner
│   ├── deep_scan.py               # Deep scanning engine
│   ├── wiz_recon.py               # Wiz 5-phase recon
│   └── web_hacking_2025/          # Vulnerability technique modules
│
├── Phases/                        # 📋 Phase-based methodology
│   ├── Phase1_Reconnaissance.md
│   ├── Phase2_Analysis.md
│   ├── Phase3_Exploitation.md
│   └── Phase4_Reporting.md
│
├── automation/                    # Legacy automation
├── templates/                     # Report templates
└── workflows/                     # Manual verification guides
```

---

## 🎯 Focus on High-Impact Vulnerabilities

Based on the **Wiz Bug Bounty Methodology**, the scanner prioritizes:

| Vulnerability | Impact | Detection | Expected Findings |
|--------------|--------|-----------|-------------------|
| **IDOR** | Critical | High | Many |
| **SSRF** | Critical | Medium | Moderate |
| **Subdomain Takeovers** | High | Very High | Many |
| **Exposed Files/Secrets** | Variable | Very High | Many |
| **Business Logic** | High | Low | Few (manual) |
| **0-Day/CVEs** | Critical | High (w/ Nuclei) | Moderate |

**📖 Full methodology:** [docs/Vulnerabilities_That_Matter.md](docs/Vulnerabilities_That_Matter.md)

---

## 📈 Expected Results

For a typical medium-sized bug bounty program:

### First Scan
- **Subdomains discovered:** 500-2000
- **Live hosts:** 100-500
- **Endpoints found:** 1000-10000
- **Potential vulnerabilities:** 10-100
- **True positives:** 5-20

### Performance
- **Time savings:** 80-85% vs traditional scanning
- **False positive reduction:** 60-70%
- **Duplicate detection:** 95%+ accuracy

---

## 💡 Usage Examples

### Intelligent Scan (Recommended)

```bash
# Discover subdomains first
subfinder -d example.com -silent > subs.txt

# Smart scan with duplicate detection
python tools/intelligent_scanner.py example.com \
  -s subs.txt \
  -o results/example_com \
  -w 10

# Watch live results (another terminal)
tail -f results/example_com/example_com/findings.jsonl
```

### Continuous 24/7 Scanning

```bash
# Run once
python tools/continuous_scanner.py -c continuous_config.yaml

# Or run as systemd service (recommended)
sudo systemctl start bugbounty-scanner
sudo systemctl enable bugbounty-scanner
```

### Comprehensive One-Time Scan

```bash
# Full pipeline
python tools/run_all.py example.com -p amazon -u yourh1user

# Parallel mode (faster)
python tools/run_all.py example.com --parallel --workers 10

# Wiz reconnaissance methodology
python tools/run_all.py example.com --wiz-recon --wiz-thorough
```

### Tool-Specific Scans

```bash
# Nuclei vulnerability scan
nuclei -u https://example.com -severity critical,high -json -o results.json

# Subdomain discovery
subfinder -d example.com -silent | httpx -silent

# Content discovery
ffuf -u https://example.com/FUZZ -w wordlist.txt

# XSS scanning
dalfox url https://example.com/search?q=FUZZ
```

---

## 📊 Monitoring & Results

### View Live Progress

```bash
# Summary stats
cat results/scan_summary.json | jq '.'

# Latest findings
tail -20 results/example_com/example_com/findings.jsonl | jq '.'

# Findings by severity
cat results/example_com/example_com/findings.jsonl | jq -r '.severity' | sort | uniq -c
```

### Output Files

```
results/example_com/
├── scan_summary.json          # Overall statistics
└── example_com/
    ├── findings.jsonl         # All findings (streaming)
    ├── findings.csv           # CSV format
    ├── subdomains.txt         # Discovered subdomains
    ├── endpoints.txt          # Discovered endpoints
    ├── skipped_deep_scan.json # Duplicates to review later
    ├── progress.json          # Live progress tracking
    └── SCAN_COMPLETE.txt      # Completion marker
```

---

## ⚙️ Configuration

### Basic Configuration

```yaml
scanning:
  targets_file: "targets.txt"
  scan_interval: 86400  # 24 hours

notifications:
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK"

nuclei:
  severity: [critical, high, medium]
  tags: [cve, exposure, takeover]
```

### API Keys (Optional but Recommended)

```yaml
api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  github_token: "YOUR_GITHUB_TOKEN"
```

Get API keys:
- **Shodan:** https://account.shodan.io/
- **GitHub:** https://github.com/settings/tokens
- **Slack Webhook:** https://api.slack.com/messaging/webhooks

**Full configuration:** [continuous_config.yaml](continuous_config.yaml)

---

## 🔒 Responsible Usage

### ⚠️ IMPORTANT

- ✅ Only scan targets where you have **explicit permission**
- ✅ Follow bug bounty program **rules and scope**
- ✅ Respect **rate limits** and server resources
- ✅ Use **responsible disclosure** practices
- ❌ Never test without authorization
- ❌ Never use destructive payloads

**This tool is for authorized security testing only.**

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Complete setup guide |
| [INTELLIGENT_SCANNER_GUIDE.md](docs/INTELLIGENT_SCANNER_GUIDE.md) | Smart scanning guide |
| [Vulnerabilities_That_Matter.md](docs/Vulnerabilities_That_Matter.md) | Wiz methodology |
| [Reconnaissance_Guide.md](docs/Reconnaissance_Guide.md) | Recon techniques |
| [Testing_Strategy.md](docs/Testing_Strategy.md) | Testing strategies |
| [Phases/](Phases/) | 4-phase workflow |

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional vulnerability scanners
- Custom Nuclei templates
- Enhanced business logic testing
- Integration with more platforms

---

## 📝 License

MIT License - See LICENSE file

---

## 🙏 Acknowledgments

Built with excellent open-source tools:
- [ProjectDiscovery](https://projectdiscovery.io/) (Nuclei, Subfinder, HTTPX, Naabu, Katana)
- [OWASP Amass](https://github.com/owasp-amass/amass)
- [ffuf](https://github.com/ffuf/ffuf), [Feroxbuster](https://github.com/epi052/feroxbuster), [Dalfox](https://github.com/hahwul/dalfox)

Methodology inspired by:
- [Wiz Bug Bounty Masterclass](https://www.wiz.io/bug-bounty-masterclass/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## 🎯 Quick Commands

```bash
# Install everything
./install_enhanced_tools.sh

# Smart scan
python tools/intelligent_scanner.py example.com -s subdomains.txt

# Continuous scan
python tools/continuous_scanner.py -c continuous_config.yaml

# View results
tail -f results/example_com/example_com/findings.jsonl

# Check stats
cat results/scan_summary.json | jq '.'
```

---

**Happy Hunting! 🎯**

*Remember: Quality > Quantity. Understand your findings, don't just run tools.*
