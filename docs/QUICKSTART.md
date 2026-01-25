# Bug Bounty Automation - Quick Start Guide

## 🚀 Getting Started

This guide will help you set up and run your enhanced bug bounty automation system for continuous, 24/7 operation.

---

## Step 1: Installation (Kali Linux)

### 1.1 Install Enhanced Tools

```bash
cd /path/to/bugbounty
chmod +x install_enhanced_tools.sh
./install_enhanced_tools.sh
```

This will install:
- 🔍 **Reconnaissance**: subfinder, amass, assetfinder, httpx, naabu
- 🎯 **Vulnerability Scanning**: Nuclei (4000+ templates), nikto, sqlmap
- 🌐 **Content Discovery**: ffuf, feroxbuster, waybackurls, gau
- 💉 **XSS/Injection**: dalfox, XSStrike
- 📊 **API Testing**: kiterunner, arjun
- 📜 **JavaScript Analysis**: LinkFinder, retire.js
- ☁️ **Cloud Security**: cloud_enum, s3scanner

### 1.2 Source Your Environment

```bash
source ~/.bashrc
```

### 1.3 Verify Installation

```bash
# Check critical tools
nuclei -version
subfinder -version
ffuf -version
```

---

## Step 2: Configuration

### 2.1 Create Targets File

```bash
# Create a file with your targets (one domain per line)
nano targets.txt
```

Example `targets.txt`:
```
example.com
test.com
api.example.com
```

### 2.2 Configure Scanner

Edit `continuous_config.yaml`:

```bash
nano continuous_config.yaml
```

**Critical settings to update:**

```yaml
scanning:
  targets_file: "targets.txt"
  scan_interval: 86400  # 24 hours

# Add your notification webhooks
notifications:
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK"
  # Or Discord:
  discord_webhook: "https://discord.com/api/webhooks/YOUR/WEBHOOK"

# Add API keys (optional but recommended)
api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  github_token: "YOUR_GITHUB_TOKEN"
```

### 2.3 Get API Keys (Optional but Recommended)

- **Shodan**: https://account.shodan.io/
- **GitHub Token**: https://github.com/settings/tokens (for subdomain discovery)
- **Slack Webhook**: https://api.slack.com/messaging/webhooks
- **Discord Webhook**: Server Settings → Integrations → Webhooks

---

## Step 3: Running the Scanner

### Option 1: One-Time Scan (Test First)

```bash
# Test with a single target
python tools/run_all.py example.com -p amazon -u yourh1user
```

### Option 2: Continuous Scanning (Recommended)

```bash
# Run continuously with your config
python tools/continuous_scanner.py -c continuous_config.yaml
```

This will:
- ✅ Run forever without timeout
- ✅ Scan all targets every 24 hours
- ✅ Detect new subdomains and vulnerabilities
- ✅ Send alerts for critical/high findings
- ✅ Store results in SQLite database
- ✅ Automatically deduplicate findings

### Option 3: Run as Background Service (Best for 24/7)

#### Create systemd service:

```bash
sudo nano /etc/systemd/system/bugbounty-scanner.service
```

Add this content:

```ini
[Unit]
Description=Bug Bounty Continuous Scanner
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/home/kali/work/BugBounty/bugbounty/bugbounty
ExecStart=/usr/bin/python3 tools/continuous_scanner.py -c continuous_config.yaml
Restart=always
RestartSec=60
StandardOutput=append:/var/log/bugbounty-scanner.log
StandardError=append:/var/log/bugbounty-scanner-error.log

[Install]
WantedBy=multi-user.target
```

#### Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable bugbounty-scanner

# Start the service
sudo systemctl start bugbounty-scanner

# Check status
sudo systemctl status bugbounty-scanner

# View logs
sudo journalctl -u bugbounty-scanner -f
```

#### Service Management Commands:

```bash
# Stop the scanner
sudo systemctl stop bugbounty-scanner

# Restart the scanner
sudo systemctl restart bugbounty-scanner

# Disable auto-start
sudo systemctl disable bugbounty-scanner
```

---

## Step 4: Monitoring Results

### 4.1 View Live Output

```bash
# If running in foreground
# Just watch the terminal output

# If running as service
sudo journalctl -u bugbounty-scanner -f
```

### 4.2 Check the Database

```bash
# View all findings
sqlite3 results/continuous/findings.db "SELECT * FROM findings ORDER BY first_seen DESC LIMIT 10;"

# Count by severity
sqlite3 results/continuous/findings.db "SELECT severity, COUNT(*) FROM findings GROUP BY severity;"

# New findings (last 24h)
sqlite3 results/continuous/findings.db "SELECT target, vulnerability_type, severity FROM findings WHERE first_seen >= datetime('now', '-1 day');"

# Unreported critical/high findings
sqlite3 results/continuous/findings.db "SELECT * FROM findings WHERE severity IN ('critical', 'high') AND reported = 0;"
```

### 4.3 Output Files

Results are saved in:
```
results/continuous/
├── findings.db              # SQLite database with all findings
├── continuous_scanner.log   # Main log file
├── nuclei_*.json           # Nuclei scan results per target
└── deep_scan/              # Deep scan results
    └── [target]/
        ├── subdomains.txt
        ├── endpoints.txt
        └── ...
```

---

## Step 5: Understanding the Tools

### Key Tools and Their Purpose

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **Nuclei** | Vulnerability scanning (4000+ templates) | Always - this finds most vulnerabilities |
| **Subfinder** | Fast subdomain discovery (40+ sources) | Find all subdomains to expand attack surface |
| **Amass** | Comprehensive subdomain discovery | When you need thorough enumeration |
| **ffuf** | High-speed content discovery | Find hidden endpoints, files, directories |
| **httpx** | HTTP probe for alive hosts | Validate which subdomains are alive |
| **Naabu** | Fast port scanning | Discover exposed services |
| **Dalfox** | Advanced XSS detection | Find XSS vulnerabilities with WAF bypass |
| **Katana** | Web crawler | Discover endpoints by crawling |
| **Arjun** | Parameter discovery | Find hidden API parameters |
| **Waybackurls** | Historical URL discovery | Find old/forgotten endpoints |

### Scan Flow

```
1. Subdomain Discovery
   └─> subfinder, assetfinder, amass
       └─> Find all subdomains

2. DNS Resolution & Validation
   └─> puredns, httpx
       └─> Check which are alive

3. Port Scanning (if enabled)
   └─> naabu
       └─> Find exposed services

4. Content Discovery
   └─> ffuf, katana, waybackurls
       └─> Find hidden endpoints

5. Vulnerability Scanning
   └─> Nuclei (PRIMARY)
       └─> 4000+ checks for CVEs, misconfigs, exposures
   └─> Dalfox (XSS)
   └─> SQLMap (SQL Injection)
   └─> Custom checks

6. Results
   └─> Store in database
   └─> Send alerts
   └─> Deduplicate
```

---

## Step 6: Optimizing for Best Results

### 6.1 Adjust Scan Interval

For different target types:

```yaml
# Active programs with frequent changes
scan_interval: 43200  # 12 hours

# Stable programs
scan_interval: 86400  # 24 hours

# Slow-changing programs
scan_interval: 259200  # 3 days
```

### 6.2 Resource Management

Monitor system resources:

```bash
# Check CPU/Memory usage
htop

# If scanner is consuming too much:
# Edit continuous_config.yaml

scanning:
  max_cpu: 60       # Lower limit
  max_memory: 60    # Lower limit

performance:
  max_workers: 3    # Reduce concurrent scans
```

### 6.3 Reduce False Positives

```yaml
# Only scan for high-value vulnerabilities
nuclei:
  severity:
    - critical
    - high
  tags:
    - cve
    - exposure
    - takeover
    # Remove 'misconfig' if too noisy
```

### 6.4 Focus on High-Impact Vulnerabilities

Based on the Wiz methodology, prioritize:

1. **IDOR** - Test ID parameters
2. **SSRF** - Test URL input features
3. **Subdomain Takeovers** - Check CNAMEs
4. **Exposed Files** - `.env`, `.git`, backups
5. **Business Logic** - Workflow flaws
6. **0-Day/CVEs** - Recent disclosures

---

## Step 7: Advanced Usage

### 7.1 Run Specific Phases Only

```bash
# Only reconnaissance (find subdomains)
python tools/run_all.py example.com --skip-web --skip-ports --skip-endpoints

# Only Nuclei vulnerability scan
nuclei -u https://example.com -severity critical,high -json -o results.json

# Only content discovery
ffuf -u https://example.com/FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt
```

### 7.2 Custom Nuclei Scans

```bash
# Scan for specific vulnerability types
nuclei -u https://example.com -tags cve -severity critical,high

# Scan for exposed panels
nuclei -u https://example.com -tags exposure,panel

# Scan for subdomain takeovers
nuclei -u https://example.com -tags takeover

# Use custom templates
nuclei -u https://example.com -t ./custom-templates/
```

### 7.3 Parallel Mode (Faster)

```bash
# Scan subdomains as they're discovered
python tools/run_all.py example.com --parallel --workers 10
```

### 7.4 Wiz Reconnaissance Mode

```bash
# Use Wiz 5-phase methodology
python tools/run_all.py example.com --wiz-recon

# Quick mode (faster)
python tools/run_all.py example.com --wiz-recon --wiz-quick

# Thorough mode (more comprehensive)
python tools/run_all.py example.com --wiz-recon --wiz-thorough
```

---

## Step 8: Best Practices

### 8.1 Always Follow Program Rules

✅ **DO:**
- Read and understand the program scope
- Only test in-scope assets
- Respect rate limits
- Report responsibly

❌ **DON'T:**
- Test out-of-scope assets
- Use destructive payloads
- Ignore rate limits
- Publicly disclose before fix

### 8.2 Start Small, Scale Up

```
Week 1: Test with 1-2 targets
Week 2: Add more targets if stable
Week 3: Enable 24/7 continuous scanning
Week 4: Optimize based on findings
```

### 8.3 Review and Verify Findings

Not all scanner results are valid:

1. **Check the evidence** - Does it actually show a vulnerability?
2. **Verify manually** - Reproduce the finding yourself
3. **Assess impact** - Is it actually exploitable?
4. **Check for duplicates** - Has it been reported before?

### 8.4 Keep Tools Updated

```bash
# Update Nuclei templates (do this weekly)
nuclei -update-templates

# Update Go tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update SecLists
cd /opt/SecLists && sudo git pull
```

---

## Troubleshooting

### Scanner Not Finding Anything

1. **Check targets file exists and has domains**
2. **Verify tools are installed**: `nuclei -version`, `subfinder -version`
3. **Check internet connectivity**
4. **Review logs**: `tail -f results/continuous/continuous_scanner.log`

### High CPU/Memory Usage

1. **Reduce workers**: Set `max_workers: 2` in config
2. **Reduce scan frequency**: Increase `scan_interval`
3. **Disable resource-heavy tools**: Comment out `amass` in config

### No Notifications Received

1. **Verify webhook URLs are correct**
2. **Check severity filter**: Only `critical` and `high` send alerts by default
3. **Test webhook manually**: `curl -X POST -H 'Content-Type: application/json' -d '{"text":"Test"}' YOUR_WEBHOOK_URL`

### Database Locked Errors

1. **Only run one scanner instance at a time**
2. **Check for other processes**: `lsof findings.db`

---

## Next Steps

1. ✅ Install tools using `install_enhanced_tools.sh`
2. ✅ Configure `continuous_config.yaml` with your targets
3. ✅ Run a test scan: `python tools/run_all.py example.com`
4. ✅ Set up notifications (Slack/Discord)
5. ✅ Enable continuous scanning as a service
6. ✅ Monitor results and refine configuration

---

## Getting Help

- **Logs**: Check `results/continuous/continuous_scanner.log`
- **Database**: Query `findings.db` for stored results
- **System Resources**: Use `htop` to monitor CPU/memory

---

## Summary of Key Files

| File | Purpose |
|------|---------|
| `install_enhanced_tools.sh` | Install all bug bounty tools |
| `continuous_config.yaml` | Main configuration file |
| `tools/continuous_scanner.py` | 24/7 continuous scanner |
| `tools/run_all.py` | One-time comprehensive scan |
| `targets.txt` | List of domains to scan |
| `findings.db` | SQLite database with results |

---

**Happy Hunting! 🎯**

Remember: Quality > Quantity. Focus on understanding the vulnerabilities you find rather than just running automated tools.
