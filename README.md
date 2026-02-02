# Bug Bounty Scanner & Intelligence Suite

A comprehensive, automated bug bounty reconnaissance and vulnerability scanning suite designed for the modern "Recursive Hacking Intelligence" methodology.

## 🚀 Key Features

### 🧠 Intelligent Reconnaissance
- **Recursive JS Analysis**: Deep-dive into JavaScript files to find hidden API endpoints, secrets, and DOM sinks.
- **Cloud Enumeration**: Automatically finds S3 buckets, Azure Blobs, and GCS buckets with permission checking.
- **Smart Tech Detection**: Identifies frameworks and tech stacks to tailor attacks.

### 🛡️ Advanced Evasion & Detection
- **WAF Evasion**: Automatically detects WAFs (Cloudflare/AWS) and applies evasion techniques (encoding, IP spoofing, adaptive delays).
- **Out-of-Band (OOB) Detection**: Integrated support for blind vulnerabilities (SSRF, XXE, SQLi) via `interact.sh` or custom callbacks.
- **False Positive Filtering**: Smart detection logic to filter out soft 404s, auth redirects, and generic errors.

### 🎯 Vulnerability Scanning
- **Context-Aware Fuzzing**: Selects payloads based on the detected technology (e.g., PHP vs Java).
- **Template Deduplication**: Hashes page structures to avoid scanning the same page type multiple times.
- **Safety First**: Non-destructive payloads designed for bug bounty programs (Amazon VRP, etc.).

## 🛠️ Usage

### 1. Unified CLI (`scanner.py`)
The main entry point for all scanning modes.

```bash
# Deep Scan (Comprehensive)
python scanner.py deep example.com -p amazon

# Intelligent Scan (Smart duplicates detection)
python scanner.py intelligent example.com -s subdomains.txt

# Asset Discovery Only (Fast)
python scanner.py discover example.com

# Wiz-style Reconnaissance
python scanner.py recon example.com --thorough
```

### 2. Configuration-Driven Scan (Recommended)
Use a YAML file to define exact scan parameters, targets, headers, and phases.

```bash
# Review and run with config
python config_scanner.py scan_config.yaml

# Or directly via CLI
python scanner.py deep -c scan_config.yaml
```

### 3. Advanced Options
Control specific phases and behaviors:

```bash
# Skip specific phases
python scanner.py deep example.com --skip-cloud --skip-waf --skip-ports

# Custom Identity
python scanner.py deep example.com -u my_h1_username --program shopify
```

## 📂 Project Structure

- `tools/discovery/`: Recon tools (Cloud buckets, Subdomains)
- `tools/analysis/`: Analysis engines (JS, Tech, Fuzzing)
- `tools/techniques/`: Advanced techniques (WAF Evasion)
- `tools/verification/`: Verification modules (OOB, Detectors)
- `tools/utils/`: Shared utilities (Config, Scope)

## ⚠️ Disclaimer
This tool is for authorized bug bounty research only. Ensure you have permission to scan the target. Follow all program rules and scopings.
