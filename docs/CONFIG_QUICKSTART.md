# Configuration-Based Scanner Quick Start Guide

## ✨ New Feature: Configuration Files!

Instead of remembering long command-line arguments, you can now:
1. Edit a configuration file
2. Review your settings
3. Confirm and run

## 📝 How It Works

### Step 1: Edit Configuration File

Open `scan_config.yaml` and customize:

```yaml
program: "anduril"
h1_username: "your_h1_username"  # ← CHANGE THIS!

targets:   # ← ADD YOUR TARGETS
  - "anduril.com"
  - "app.anduril.com"

custom_headers:
  X-HackerOne-Research: "your_h1_username"  # ← CHANGE THIS!

phases:
  subdomain_discovery: true   # ← Enable/disable phases
  verification: true
```

### Step 2: Run Scanner

```bash
python config_scanner.py scan_config.yaml
```

### Step 3: Review Output

The scanner shows you a **COMPLETE REVIEW** before running:

```
================================================================================
                    🔍 SCAN CONFIGURATION REVIEW
================================================================================

📋 PROGRAM INFORMATION
   Program: ANDURIL
   H1 Username: your_h1_username

🎯 TARGETS (2)
   1. anduril.com
   2. app.anduril.com

📤 CUSTOM HEADERS (1)
   X-HackerOne-Research: your_h1_username

⏱️  RATE LIMITING
   Rate Limit: 5 req/sec
   Request Delay: 0.2s
   Request Timeout: 30s

✅ ENABLED PHASES (7/7)
   ✓ Phase 1: Subdomain Discovery
   ✓ Phase 2: Port Scanning
   ✓ Phase 3: Endpoint Discovery
   ✓ Phase 4: Technology Detection
   ✓ Phase 5: JavaScript Analysis
   ✓ Phase 6: Parameter Fuzzing
   ✓ Phase 7: Vulnerability Verification

📊 SCAN LIMITS
   Max Subdomains: Unlimited
   Max Endpoints: Unlimited
   Max JS Files: Unlimited

🔌 PORT SCANNING
   Full Port Scan: Yes
   Custom Ports: None

🔍 VERIFICATION SETTINGS
   Threads: 10
   High Priority Only: No
   Test Default Creds: No (safe)

💾 OUTPUT SETTINGS
   Directory: F:/work/BugBounty/Target/Anduril Industries/scan_results
   Save JSON: Yes
   Save TXT: Yes
   Verbose: Yes

🛡️  SAFETY SETTINGS
   Confirm Before Run: Yes
   Max Threads: 10

📝 NOTES
   Anduril Industries Bug Bounty Scan
   - Defense contractor - be extra cautious
   - Required header: X-HackerOne-Research
   - NO data exfiltration

================================================================================
   Scan will start at: 2026-01-28 22:41:00
================================================================================

❓ Proceed with scan? [Y/n/review]:
```

### Step 4: Confirm

- Type `y` or press Enter to **START**
- Type `n` to **CANCEL**
- Type `review` to **SEE REVIEW AGAIN**

## 🎯 Quick Examples

### Example 1: Anduril Full Scan

```bash
# 1. Edit config
notepad scan_config.yaml

# 2. Set your settings
program: "anduril"
h1_username: "myusername"
targets: ["anduril.com"]
custom_headers:
  X-HackerOne-Research: "myusername"

# 3. Run
python config_scanner.py scan_config.yaml

# 4. Review and confirm
[Y/n/review]: y
```

### Example 2: Quick Recon (No Fuzzing)

Create `quick_recon.yaml`:
```yaml
program: "anduril"
h1_username: "myusername"
targets: ["anduril.com"]

phases:
  subdomain_discovery: true
  port_scanning: true
  endpoint_discovery: true
  tech_detection: true
  js_analysis: true
  param_fuzzing: false     # ← SKIP
  verification: false      # ← SKIP
```

Run:
```bash
python config_scanner.py quick_recon.yaml
```

###Example 3: Verification Only

Create `verify_only.yaml`:
```yaml
program: "anduril"
targets: ["app.anduril.com"]

phases:
  subdomain_discovery: false
  port_scanning: false
  endpoint_discovery: false
  tech_detection: false
  js_analysis: false
  param_fuzzing: false
  verification: true       # ← ONLY THIS

verification:
  threads: 20
```

## 📋 Config File Sections

| Section | Purpose | Example |
|---------|---------|---------|
| `program` | Bug bounty program name | `"anduril"`, `"amazon"`, `"shopify"` |
| `h1_username` | Your HackerOne username | `"yourname"` |
| `targets` | List of domains/IPs to scan | `["anduril.com", "api.anduril.com"]` |
| `custom_headers` | HTTP headers to add | `X-HackerOne-Research: "yourname"` |
| `phases` | Enable/disable scan phases | `subdomain_discovery: true` |
| `limits` | Set max limits | `max_endpoints: 100` |
| `verification` | Verification settings | `threads: 10` |
| `output` | Where to save results | `directory: "path/to/results"` |
| `safety` | Safety features | `confirm_before_run: true` |

## 🔥 Benefits

✅ **No more long commands**  
Instead of:
```bash
python scanner.py deep -t anduril.com --program anduril --username myname --skip-fuzz --skip-js ...
```

Just:
```bash
python config_scanner.py my_config.yaml
```

✅ **Review before running**  
See exactly what will happen before the scan starts

✅ **Reusable configs**  
Save configs for different programs/scenarios

✅ **Version control**  
Track your scan configs in Git

✅ **Safety first**  
Always confirm before running

## 💡 Pro Tips

1. **Create templates for each program:**
   ```
   anduril_template.yaml
   amazon_template.yaml
   shopify_template.yaml
   ```

2. **Use descriptive names:**
   ```
   anduril_recon_2026-01-28.yaml
   anduril_deep_scan.yaml
   anduril_verify_findings.yaml
   ```

3. **Keep a library:**
   ```
   configs/
   ├── anduril/
   │   ├── full_scan.yaml
   │   ├── quick_recon.yaml
   │   └── verify_only.yaml
   ├── amazon/
   └── shopify/
   ```

4. **Test with review:**
   Always enable `show_review: true` and `confirm_before_run: true` for first runs

## 🛠️ Installation

Make sure you have PyYAML installed:
```bash
pip install pyyaml
```

## 📚 More Information

- **Full config reference:** See `scan_config.yaml` (commented)
- **Templates:** See `CONFIG_TEMPLATES.md`
- **Program-specific guides:** See program folders

## 🚀 Ready to Start?

```bash
cd F:\work\BugBounty\bugbounty\bugbounty

# 1. Edit the config
notepad scan_config.yaml

# 2. Update your settings
# - Change h1_username
# - Add your targets
# - Configure headers

# 3. Run with review
python config_scanner.py scan_config.yaml

# 4. Review and confirm!
```

That's it! Much simpler than remembering all the command-line arguments! 🎉
