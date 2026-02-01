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

### 1. Cloud Storage Enumeration
Find hidden buckets associated with a target domain.
```bash
python -m tools.discovery.cloud_enum example.com
```

### 2. Recursive JavaScript Analysis
Deep analysis of JS files to find endpoints and secrets.
```bash
python -m tools.analysis.js_analyzer https://example.com --recursive --depth 2
```

### 3. WAF Detection & Evasion
Check for WAFs and generate evasion payloads.
```bash
python -m tools.techniques.waf_evasion --url https://example.com
```

### 4. Full Scan (Integrated)
Run the complete scanner with all modules enabled.
```bash
python scanner.py --config scan_config.yaml
```

## 📂 Project Structure

- `tools/discovery/`: Recon tools (Cloud buckets, Subdomains)
- `tools/analysis/`: Analysis engines (JS, Tech, Fuzzing)
- `tools/techniques/`: Advanced techniques (WAF Evasion)
- `tools/verification/`: Verification modules (OOB, Detectors)
- `tools/utils/`: Shared utilities (Config, Scope)

## ⚠️ Disclaimer
This tool is for authorized bug bounty research only. Ensure you have permission to scan the target. Follow all program rules and scopings.
