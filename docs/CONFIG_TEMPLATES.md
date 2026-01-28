# Quick Configuration Templates

Create different config files for different programs and scenarios!

## Quick Start

1. **Copy a template:**
   ```bash
   cp scan_config.yaml my_scan.yaml
   ```

2. **Edit the file:**
   - Set your targets
   - Configure headers
   - Choose scan phases
   
3. **Review and run:**
   ```bash
   python config_scanner.py my_scan.yaml
   ```

## Available Templates

### 1. Anduril Industries (Defense Contractor)
**File:** `scan_config.yaml` (default)
- Required header: `X-HackerOne-Research`
- Conservative rate limiting (5 req/sec)
- All safety features enabled
- Full 7-phase scan

### 2. Amazon VRP (Quick Template)
```yaml
program: "amazon"
h1_username: "your_h1_username"
targets:
  - "amazonpayinsurance.in"
custom_headers: {}  # Amazon uses custom User-Agent, not headers
rate_limit: 5
phases:
  subdomain_discovery: true
  verification: true
```

### 3. Shopify (Quick Template)
```yaml
program: "shopify"
h1_username: "your_h1_username"
targets:
  - "shop.app"
rate_limit: 10
verification:
  threads: 15
```

### 4. Generic Program (No Program-Specific Rules)
```yaml
program: null
targets:
  - "example.com"
custom_headers:
  X-Bug-Bounty-Research: "your_name"
rate_limit: 5
```

### 5. Quick Recon (Fast, No Fuzzing)
```yaml
program: "anduril"
targets:
  - "anduril.com"
phases:
  subdomain_discovery: true
  port_scanning: true
  endpoint_discovery: true
  tech_detection: true
  js_analysis: false
  param_fuzzing: false
  verification: false
```

### 6. Verification Only (Test Previous Findings)
```yaml
program: "anduril"
targets:
  - "app.anduril.com"
phases:
  subdomain_discovery: false
  port_scanning: false
  endpoint_discovery: true
  tech_detection: false
  js_analysis: false
  param_fuzzing: false
  verification: true  # Only verify
verification:
  threads: 20
```

## Common Scenarios

### Scenario 1: First Scan on New Program
```yaml
# Conservative, thorough scan with all safety features
safety:
  confirm_before_run: true
  show_review: true
phases:
  # All phases enabled
verification:
  test_default_credentials: false  # SAFE
```

### Scenario 2: Deep Dive on Specific Subdomain
```yaml
targets:
  - "api.anduril.com"
limits:
  max_subdomains: 10  # Don't discover too many
  max_endpoints: 500  # Focus on existing
phases:
  subdomain_discovery: false  # Skip subdomain enum
  endpoint_discovery: true
  param_fuzzing: true
  verification: true
```

### Scenario 3: Port Scan Only
```yaml
targets:
  - "anduril.com"
phases:
  subdomain_discovery: true
  port_scanning: true
  endpoint_discovery: false
  tech_detection: false
  js_analysis: false
  param_fuzzing: false
  verification: false
port_scan:
  full_scan: true
  custom_ports: [8080, 8443, 3000, 5000]
```

## Tips

1. **Start with review enabled:** Always review your config before running
2. **Use descriptive names:** `anduril_full_scan_2026-01-28.yaml`
3. **Keep templates:** Save successful configs as templates
4. **Version control:** Track your config files in Git
5. **Test first:** Do a small scan before full program scan

## Safety Checklist

Before running any scan:
- [ ] Correct program selected
- [ ] H1 username set correctly
- [ ] Required headers configured
- [ ] Targets are in-scope
- [ ] Rate limiting appropriate
- [ ] Output directory set
- [ ] Review enabled
- [ ] Reviewed program rules

## Example Workflow

```bash
# 1. Copy template
cp scan_config.yaml anduril_scan_2026-01-28.yaml

# 2. Edit in your favorite editor
notepad anduril_scan_2026-01-28.yaml

# 3. Review and run
python config_scanner.py anduril_scan_2026-01-28.yaml

# The scanner will show you:
# - All targets
# - All headers
# - Which phases will run
# - Rate limits
# - Safety settings

# 4. Confirm or cancel
# [Y/n/review]: y

# 5. Scan runs!
```

## Advanced: Multiple Configs

Run different configs in sequence:

```bash
# Morning: Quick recon
python config_scanner.py recon_morning.yaml

# Afternoon: Deep endpoints
python config_scanner.py deep_afternoon.yaml

# Evening: Verification
python config_scanner.py verify_evening.yaml
```

## Troubleshooting

**"Config file not found"**
- Check the file path
- Make sure it ends with `.yaml`

**"Invalid YAML"**
- Check indentation (use spaces, not tabs)
- Validate at yamllint.com

**"Header not being sent"**
- Check custom_headers section
- Make sure key-value format is correct

**"Rate limit too high"**
- Check program rules
- Use conservative values (5 req/sec)
