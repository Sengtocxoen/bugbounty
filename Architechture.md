# Bug Bounty Scanner — Full Architecture

> **"Recursive Hacking Intelligence"** engine implementing the Deep-Dive methodology.
> Single CLI entry point (`scanner.py`) → Config-driven → 13 scan modes → 60+ modules.

**Related docs:** [Layer.md](Layer.md) (execution stack) · [Feature.md](Feature.md) (capabilities) · [Agent.md](Agent.md) (methodology)

---

## 1. High-Level System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER / OPERATOR                            │
│   scan_config.yaml  ──►  scanner.py (CLI Entry Point)              │
│                          ├── Mode Selection (13 modes)             │
│                          ├── Config Resolution                     │
│                          └── Target Resolution                     │
└────────────────┬────────────────────────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │  ORCHESTRATION   │
        │  Layer           │
        │  ─────────────── │
        │  scanner.py      │  Config helpers, mode dispatch,
        │  (1,199 lines)   │  parallel execution, HTML report gen
        └────────┬────────┘
                 │
    ┌────────────┼─────────────────────────────────────┐
    │            │            │            │            │
    ▼            ▼            ▼            ▼            ▼
┌────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐
│DISCOVER│ │ ANALYSIS│ │ SCANNERS │ │TECHNIQUES│ │VERIFY  │
│  (10)  │ │  (14)   │ │   (10)   │ │   (19)   │ │ (13)   │
└────────┘ └─────────┘ └──────────┘ └──────────┘ └────────┘
    │            │            │            │            │
    └────────────┼─────────────────────────────────────┘
                 │
        ┌────────▼────────┐     ┌──────────────┐
        │    UTILITIES     │     │  REPORTING   │
        │   (10 modules)   │     │  (HTML)      │
        └─────────────────┘     └──────────────┘
```

---

## 2. Directory Structure

```
bugbounty/
├── scanner.py                  # 🎯 Main CLI entry point (all 13 modes)
├── scan_config.yaml            # Per-program config (gitignored)
├── scan_config.yaml.test       # Template config
├── auto_scan.sh                # Shell automation wrapper
├── run_all_scans.sh            # Batch scan launcher
├── run_nuclei.py               # Standalone Nuclei runner
├── nuclei-auth.yaml            # Nuclei auth config
├── requirements.txt            # Python dependencies
├── configs/                    # Program-specific YAML configs
│
├── tools/
│   ├── __init__.py             # Package init & path setup
│   ├── scanner.py              # Secondary scanner (tools-level)
│   ├── aggregate_results.py    # Result aggregation across scans
│   │
│   ├── discovery/              # 🔍 Reconnaissance & Asset Discovery
│   │   ├── enhanced_subdomain_scanner.py  # Permutation-based subdomain enum
│   │   ├── subdomain_discovery.py         # Standard subdomain discovery
│   │   ├── dns_deep_enum.py               # Deep DNS enumeration
│   │   ├── endpoint_discovery.py          # Hidden URL/API path hunting
│   │   ├── cloud_enum.py                  # S3/Azure/GCS bucket enumeration
│   │   ├── service_checker.py             # Port/service fingerprinting
│   │   ├── github_dorking.py              # GitHub/GitLab secret scanning
│   │   ├── osint_recon.py                 # WHOIS, emails, dorks, cloud intel
│   │   └── bug_discovery.py               # Lightweight discovery pipeline
│   │
│   ├── analysis/               # 🧠 Intelligence & Analysis
│   │   ├── js_analyzer.py                 # Recursive JS analysis + secrets
│   │   ├── tech_detection.py              # Framework fingerprinting
│   │   ├── param_fuzzer.py                # Hidden GET/POST param detection
│   │   ├── advanced_fuzzer.py             # Recursive dir fuzzing + soft-404
│   │   ├── graphql_introspection.py       # GraphQL schema mapping
│   │   ├── false_positive_detector.py     # Noise reduction engine
│   │   ├── smart_response_detector.py     # Smart response classification
│   │   ├── response_analyzer.py           # HTTP response analysis
│   │   ├── source_sink_mapper.py          # Taint analysis (source→sink)
│   │   ├── vuln_chainer.py                # Vulnerability chaining engine
│   │   ├── vuln_deep_scan.py              # Deep vuln analysis
│   │   ├── vuln_payloads.py               # Payload generation library
│   │   └── web_deep_analysis.py           # Full web app deep analysis
│   │
│   ├── scanners/               # ⚡ Core Scanner Engines
│   │   ├── deep_scan.py                   # Comprehensive deep scanner (90KB)
│   │   ├── full_recon.py                  # Full recon pipeline
│   │   ├── wiz_recon.py                   # Wiz-style 5-phase recon
│   │   ├── intelligent_scanner.py         # Two-phase smart scanner
│   │   ├── continuous_scanner.py          # 24/7 continuous scanner
│   │   ├── parallel_scan.py              # Parallel streaming scanner
│   │   ├── vuln_scanner_v2.py             # V2 vulnerability scanner (63KB)
│   │   ├── external_scanners.py           # External tool orchestrator
│   │   └── burp_wrapper.py                # Burp Suite Pro integration
│   │
│   ├── techniques/             # ⚔️ Offensive Attack Techniques
│   │   ├── waf_evasion.py                 # WAF detection & bypass
│   │   └── web_hacking_2025/              # 2025-era attack modules
│   │       ├── base.py                    # Base scanner class
│   │       ├── scanner.py                 # Web hacking orchestrator
│   │       ├── bugbounty_config.py        # Bug bounty-specific config
│   │       ├── auth_bypass.py             # Auth logic flaws & token manipulation
│   │       ├── ssrf.py                    # SSRF + OOB callbacks
│   │       ├── ssti_inject.py             # SSTI for RCE (44KB)
│   │       ├── xss_csrf.py               # XSS & CSRF testing
│   │       ├── smuggling.py               # HTTP desync (CL.TE, TE.CL)
│   │       ├── cache_poison.py            # Web cache poisoning
│   │       ├── parser_xxe.py              # XXE via parser exploitation
│   │       ├── deserialization.py          # Insecure deserialization
│   │       ├── framework_vulns.py         # Framework-specific CVEs
│   │       ├── protocol_attacks.py        # Protocol-level attacks
│   │       ├── xs_leaks.py                # Cross-site leak detection
│   │       └── run.py                     # Quick-run entry point
│   │
│   ├── verification/           # ✅ Finding Verification & Proof
│   │   ├── verification_manager.py        # Verification orchestrator
│   │   ├── nuclei_scanner.py              # Nuclei template scanner
│   │   ├── oob_detector.py                # OOB callback listener
│   │   ├── graphql_verifier.py            # GraphQL security verifier
│   │   ├── git_verifier.py                # .git exposure verifier
│   │   ├── admin_verifier.py              # Admin panel verifier
│   │   ├── api_verifier.py                # API endpoint verifier
│   │   ├── backup_verifier.py             # Backup file verifier
│   │   ├── redirect_verifier.py           # Open redirect verifier
│   │   ├── service_verifier.py            # Service security verifier
│   │   └── ssti_verifier.py               # SSTI confirmation verifier
│   │
│   ├── utils/                  # 🔧 Shared Utilities
│   │   ├── config.py                      # Program config management
│   │   ├── http_client.py                 # HTTP client with evasion
│   │   ├── external_tools.py              # External binary management
│   │   ├── tools_manager.py               # Tool installation/checking
│   │   ├── scope_validator.py             # In-scope validation
│   │   ├── response_dedup.py              # Response deduplication
│   │   ├── secret_patterns.py             # Regex patterns for secrets
│   │   ├── secret_validator.py            # Active secret validation
│   │   └── streaming_results.py           # Streaming result output
│   │
│   └── reporting/              # 📊 Report Generation
│       └── html_report.py                 # HTML report builder
│
├── books/                      # 📚 Reference material
├── deep_scan_results/          # Scan output storage
├── Agent.md                    # Project manifesto & methodology
├── Feature.md                  # Feature compendium
├── README.md                   # Usage documentation
└── SKILL.md                    # Agent skill instructions
```

---

## 3. Orchestration Layer (`scanner.py`)

The **single entry point** for all scanning operations. Config-driven — no complex CLI args.

### 3.1 Config Resolution Pipeline

```
scan_config.yaml ──► load_config() ──► Format Detection ──► Helper Extraction
                                        │                    │
                                        ├── Flat format      ├── _get_program()
                                        └── Nested format    ├── _get_rate_limit()
                                            (full_recon)     ├── _get_custom_headers()
                                                             ├── _get_nuclei_config()
                                                             ├── _get_burp_config()
                                                             └── ... (15+ helpers)
```

### 3.2 Scan Modes (13 Total)

| Mode | Runner Function | Engine | Purpose |
|:-----|:----------------|:-------|:--------|
| `deep` | `run_deep_mode()` | `deep_scan.py` | Comprehensive scan with auto HTML report |
| `fullrecon` | `run_fullrecon_mode()` | `full_recon.py` | Full reconnaissance pipeline |
| `recon` | `run_recon_mode()` | `wiz_recon.py` | Wiz-style 5-phase reconnaissance |
| `intelligent` | `run_intelligent_mode()` | `intelligent_scanner.py` | Smart two-phase scanner with dedup |
| `continuous` | `run_continuous_mode()` | `continuous_scanner.py` | 24/7 monitoring scanner |
| `discover` | `run_discover_mode()` | Subdomain/asset tools | Fast asset discovery only |
| `parallel` | `run_parallel_mode()` | `parallel_scan.py` | Parallel streaming scanner |
| `all` | `run_all_mode()` | Multiple engines | Runs multiple scanners in parallel + aggregates |
| `osint` | `run_osint_mode()` | `osint_recon.py` | WHOIS, emails, dorks, GitHub, cloud |
| `github` | `run_github_mode()` | `github_dorking.py` | GitHub/GitLab dorking for leaked secrets |
| `vuln_deep` | `run_vuln_deep_mode()` | `vuln_deep_scan.py` | Nuclei + XSS + SQLi + SSRF + CORS + LFI + SSTI |
| `bug_discovery` | `run_bug_discovery_mode()` | Pipeline | Subdomain → endpoint → tech → JS → fuzz |
| `webhack2025` | `_run_webhack2025()` | `web_hacking_2025/` | 2025-era attack techniques |

### 3.3 Execution Flow

```
main()
  ├── parse_args()
  ├── load_config(config_path)
  ├── resolve_targets(config)
  ├── resolve_subdomains(config)
  ├── print_config_summary(config, targets)
  ├── confirm_scan(config)
  ├── select_scan_mode(config)
  │
  ├── MODE_RUNNERS[mode](config, targets)     # Dispatch to runner
  │     ├── Phase execution (per mode)
  │     ├── Finding collection
  │     └── Summary printing (before Burp)
  │
  ├── Burp Suite auto-launch (if enabled)     # Post-scan Burp integration
  └── _generate_html_reports(output_dir)      # Auto HTML report
```

---

## 4. Component Architecture Details

### 4.1 🔍 Discovery Layer (`tools/discovery/`)

Foundational intelligence gathering to uncover hidden attack surfaces.

```
                    ┌──────────────────┐
                    │   Target Domain  │
                    └────────┬─────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Subdomain   │  │   Endpoint   │  │    Cloud     │
  │  Discovery   │  │  Discovery   │  │    Enum      │
  │              │  │              │  │              │
  │ • Subfinder  │  │ • URL mining │  │ • S3 buckets │
  │ • Amass      │  │ • API paths  │  │ • Azure Blob │
  │ • Permutation│  │ • Dev routes │  │ • GCS        │
  │ • DNS deep   │  │ • Wayback    │  │ • Permissions│
  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
         │                 │                 │
         ▼                 ▼                 ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │   Service    │  │   GitHub     │  │    OSINT     │
  │   Checker    │  │   Dorking    │  │    Recon     │
  │              │  │              │  │              │
  │ • Ports      │  │ • Leaked API │  │ • WHOIS      │
  │ • Versions   │  │   keys       │  │ • Emails     │
  │ • Banners    │  │ • .env files │  │ • Google dork│
  │ • Protocols  │  │ • Int. docs  │  │ • Cloud intel│
  └──────────────┘  └──────────────┘  └──────────────┘
```

**Key Modules:**

| Module | Size | Capability |
|:-------|:-----|:-----------|
| `enhanced_subdomain_scanner.py` | 42KB | Permutation scanning, multi-source, active checking |
| `endpoint_discovery.py` | 32KB | Aggressive URL/API path hunting |
| `dns_deep_enum.py` | 30KB | Deep DNS enumeration & zone analysis |
| `osint_recon.py` | 37KB | Comprehensive OSINT (WHOIS, emails, dorks) |
| `cloud_enum.py` | 13KB | S3/Azure/GCS enumeration with perm checks |
| `service_checker.py` | 18KB | Port scanning & service fingerprinting |
| `github_dorking.py` | 14KB | GitHub/GitLab repo scanning for secrets |
| `bug_discovery.py` | 17KB | Lightweight discovery pipeline orchestrator |

---

### 4.2 🧠 Analysis Layer (`tools/analysis/`)

Understanding the target's technology, logic, and attack surface.

```
┌─────────────────────────────────────────────────────────────┐
│                    ANALYSIS ENGINE                           │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ JS Analyzer │◄──►│ Tech Detect  │◄──►│ GraphQL      │   │
│  │             │    │              │    │ Introspect   │   │
│  │ • Recursive │    │ • Framework  │    │ • Schema map │   │
│  │   JS→EP→JS  │    │   fingerprint│    │ • Hidden     │   │
│  │ • Secrets   │    │ • Context-   │    │   queries    │   │
│  │   (AWS,API) │    │   aware      │    │ • Depth      │   │
│  │ • DOM sinks │    │   payloads   │    │   limits     │   │
│  └─────────────┘    └──────────────┘    └──────────────┘   │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Param Fuzzer│    │ Adv. Fuzzer  │    │ Vuln Chainer │   │
│  │             │    │              │    │              │   │
│  │ • Hidden    │    │ • Recursive  │    │ • SSRF+IDOR  │   │
│  │   params    │    │   dirs       │    │ • XSS+CSRF   │   │
│  │ • Context   │    │ • Soft-404   │    │ • LFI+RCE    │   │
│  │   wordlists │    │ • Header     │    │ • Auto-       │   │
│  │ • IDOR/SSRF │    │   injection  │    │   escalate   │   │
│  └─────────────┘    └──────────────┘    └──────────────┘   │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ FP Detector │    │Source→Sink   │    │ Vuln Payloads│   │
│  │             │    │ Mapper       │    │              │   │
│  │ • Soft 404s │    │ • Taint flow │    │ • XSS/SQLi   │   │
│  │ • Generic   │    │ • Data flow  │    │ • SSRF/SSTI  │   │
│  │   errors    │    │   analysis   │    │ • RCE/LFI    │   │
│  └─────────────┘    └──────────────┘    └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key Innovation — Recursive JS Analysis:**
```
JS File → Extract Endpoints → Crawl Endpoints → Find More JS → Repeat
                                    ↓
                          Extract Secrets (AWS, Firebase, Bearer)
                                    ↓
                          Validate Secrets (active verification)
```

---

### 4.3 ⚡ Scanner Engines (`tools/scanners/`)

Multiple scanner engines optimized for different use cases.

| Engine | Size | Strategy |
|:-------|:-----|:---------|
| `deep_scan.py` | 91KB | Most comprehensive; all phases, all techniques |
| `vuln_scanner_v2.py` | 63KB | V2 vuln scanner — Nuclei + custom checks |
| `wiz_recon.py` | 51KB | Wiz-style 5-phase recon pipeline |
| `full_recon.py` | 32KB | Full reconnaissance pipeline |
| `burp_wrapper.py` | 28KB | Burp Suite Pro headless integration via REST API |
| `external_scanners.py` | 26KB | External tool orchestrator (Nuclei, Dalfox, etc.) |
| `parallel_scan.py` | 22KB | Parallel streaming scanner for speed |
| `continuous_scanner.py` | 20KB | 24/7 monitoring with change detection |
| `intelligent_scanner.py` | 15KB | Two-phase: quick probe → targeted deep scan |

---

### 4.4 ⚔️ Techniques Layer (`tools/techniques/`)

Active exploitation using modern 2025-era attack vectors.

```
┌─────────────────────────────────────────────────────────────┐
│               WEB HACKING 2025 ARSENAL                      │
│                                                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│   │   SSRF   │  │   SSTI   │  │   XSS    │  │   Auth   │  │
│   │   + OOB  │  │  Inject  │  │  + CSRF  │  │  Bypass  │  │
│   │  (31KB)  │  │  (44KB)  │  │  (27KB)  │  │  (20KB)  │  │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│                                                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│   │ Cache    │  │ HTTP     │  │  XXE     │  │ Deseiral │  │
│   │ Poison   │  │ Smuggle  │  │ Parser   │  │ ization  │  │
│   │  (21KB)  │  │  (14KB)  │  │  (20KB)  │  │  (14KB)  │  │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│                                                             │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│   │Framework │  │ Protocol │  │ XS-Leaks │                │
│   │  Vulns   │  │ Attacks  │  │          │                │
│   │  (23KB)  │  │  (18KB)  │  │  (16KB)  │                │
│   └──────────┘  └──────────┘  └──────────┘                │
│                                                             │
│   Shared: base.py (25KB) │ scanner.py │ bugbounty_config   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────┐
│     WAF EVASION (10KB)  │
│  • Cloudflare/AWS/Akamai│
│  • IP rotation          │
│  • Header spoofing      │
│  • Encoding loops       │
│  • Tamper scripts       │
│  • Adaptive delays      │
└─────────────────────────┘
```

**Attack Coverage:**

| Category | Module | Attack Types |
|:---------|:-------|:-------------|
| Injection | `ssrf.py`, `ssti_inject.py` | SSRF, SSTI, OOB callbacks (interact.sh) |
| Client-Side | `xss_csrf.py`, `xs_leaks.py` | DOM XSS, Reflected XSS, CSRF, Cross-site Leaks |
| Auth/Access | `auth_bypass.py` | Token manipulation, IDOR, broken access control |
| Protocol | `smuggling.py`, `protocol_attacks.py` | HTTP desync (CL.TE, TE.CL), protocol abuse |
| Cache/Parser | `cache_poison.py`, `parser_xxe.py` | Web cache poisoning, XXE via parser exploit |
| Framework | `framework_vulns.py`, `deserialization.py` | Spring/Django/Log4j CVEs, unsafe deserialization |
| Evasion | `waf_evasion.py` | WAF fingerprint → auto-bypass selection |

---

### 4.5 ✅ Verification Layer (`tools/verification/`)

Every finding goes through verification to ensure **zero false positives**.

```
┌──────────────────────────────────────────────────────────────┐
│                 VERIFICATION MANAGER                         │
│            (verification_manager.py - orchestrator)           │
│                                                              │
│   Raw Findings ──► Classify ──► Route to Verifier ──► Proof  │
│                                                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│   │   Nuclei     │  │   OOB        │  │  GraphQL     │      │
│   │   Scanner    │  │  Detector    │  │  Verifier    │      │
│   │  (28KB)      │  │  (10KB)      │  │  (11KB)      │      │
│   │              │  │              │  │              │      │
│   │ • Template   │  │ • DNS/HTTP   │  │ • Introspect │      │
│   │   matching   │  │   callback   │  │ • Depth      │      │
│   │ • Tech-aware │  │ • Blind vuln │  │   limits     │      │
│   │   selection  │  │   confirm    │  │ • Auth checks│      │
│   └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│   │   Git        │  │   Admin      │  │   API        │      │
│   │  Verifier    │  │  Verifier    │  │  Verifier    │      │
│   │  (7KB)       │  │  (12KB)      │  │  (10KB)      │      │
│   └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│   │  Redirect    │  │   Service    │  │   SSTI       │      │
│   │  Verifier    │  │  Verifier    │  │  Verifier    │      │
│   │  (9KB)       │  │  (17KB)      │  │  (10KB)      │      │
│   └──────────────┘  └──────────────┘  └──────────────┘      │
│   ┌──────────────┐                                           │
│   │  Backup      │                                           │
│   │  Verifier    │                                           │
│   │  (8KB)       │                                           │
│   └──────────────┘                                           │
└──────────────────────────────────────────────────────────────┘
```

---

### 4.6 🔧 Utilities Layer (`tools/utils/`)

Shared infrastructure used across all components.

| Module | Purpose |
|:-------|:--------|
| `config.py` (10KB) | Program-specific config management |
| `http_client.py` (13KB) | HTTP client with WAF evasion, rate limiting, retries |
| `external_tools.py` (27KB) | External binary detection & execution |
| `tools_manager.py` (16KB) | Tool installation checking & management |
| `scope_validator.py` (14KB) | Target scope validation (in/out of scope) |
| `response_dedup.py` (12KB) | Response deduplication — **60% faster scans** |
| `secret_patterns.py` (12KB) | Regex patterns for AWS, Firebase, API keys, etc. |
| `secret_validator.py` (16KB) | Active validation of discovered secrets |
| `streaming_results.py` (17KB) | Real-time streaming result output |

---

### 4.7 📊 Reporting (`tools/reporting/`)

| Module | Purpose |
|:-------|:--------|
| `html_report.py` (19KB) | Generates styled HTML reports from JSON scan results |
| `aggregate_results.py` (21KB) | Cross-scan result aggregation & dedup |

---

## 5. External Tool Integrations

### 5.1 CLI Binary Arsenal

Managed via `install_all_tools.sh` / `install_enhanced_tools.sh` and orchestrated by `external_tools.py`.

| Tool | Purpose | Integration Point |
|:-----|:--------|:------------------|
| **Nuclei** | Template-based vuln scanning | `nuclei_scanner.py`, `external_scanners.py` |
| **Subfinder** | Passive subdomain enumeration | `subdomain_discovery.py` |
| **Amass** | Deep passive recon | `enhanced_subdomain_scanner.py` |
| **HTTPX** | Live probing & tech fingerprinting | Multiple scanners |
| **Interactsh** | OOB callback handling | `oob_detector.py`, `ssrf.py` |
| **Kiterunner** | API route discovery | `endpoint_discovery.py` |
| **Dalfox** | Advanced XSS scanning | `external_scanners.py` |
| **Arjun / x8** | Hidden parameter discovery | `param_fuzzer.py` |
| **FFuf** | Directory/param/vhost fuzzing | `advanced_fuzzer.py` |
| **Katana** | Web crawling | Multiple scanners |
| **Trufflehog** | Secret scanning | `github_dorking.py` |
| **Naabu** | Fast port scanning | `service_checker.py` |

### 5.2 Burp Suite Professional Integration

```
scanner.py
  └── run_deep_mode() / run_all_mode()
        ├── Print findings summary
        └── Auto-launch Burp Suite Pro
              └── burp_wrapper.py
                    ├── Headless mode via REST API
                    ├── Targeted scan of discovered endpoints
                    ├── Finding import & dedup
                    └── Result merge with custom scan data
```

**Config (`scan_config.yaml`):**
```yaml
burp_suite:
  enabled: true
  jar_path: "/path/to/burpsuite_pro.jar"
  api_port: 1337
  auto_launch: true
  scan_types: ["active", "passive"]
```

---

## 6. Data Flow Architecture

### 6.1 Deep Scan Pipeline (Most Comprehensive)

```
Phase 1: DISCOVERY
  ├── Subdomain enumeration (subfinder + amass + permutation)
  ├── DNS deep enumeration
  ├── Cloud asset enumeration (S3/Azure/GCS)
  ├── Service/port scanning
  └── Output: live_hosts.txt, subdomains.txt

Phase 2: ANALYSIS
  ├── HTTPX probing → tech detection
  ├── Endpoint discovery (wayback + katana + custom)
  ├── Recursive JS analysis → secret extraction → validation
  ├── GraphQL introspection
  ├── Parameter fuzzing
  └── Output: endpoints.json, tech_stack.json, secrets.json

Phase 3: SCANNING
  ├── Nuclei (tech-aware template selection)
  ├── Web Hacking 2025 techniques (11 attack modules)
  ├── Vuln Scanner V2 (XSS + SQLi + SSRF + SSTI + more)
  ├── WAF evasion (auto-applied when WAF detected)
  └── Output: raw_findings.json

Phase 4: VERIFICATION
  ├── Route findings to specialized verifiers
  ├── OOB callback confirmation
  ├── False positive filtering
  └── Output: verified_findings.json

Phase 5: CHAINING & REPORTING
  ├── Vulnerability chaining (auto-escalation)
  ├── Result aggregation & dedup
  ├── Summary printing
  ├── Burp Suite auto-launch (if enabled)
  └── HTML report generation
```

### 6.2 Configuration-Driven Behavior

```yaml
# scan_config.yaml structure
program: "target_program"
h1_username: "hunter"
targets:
  - "*.target.com"

rate_limit: 5
request_delay: 0.2
request_timeout: 30
max_workers: 10

custom_headers:
  X-Bug-Bounty: "hunter"

phases:
  subdomain_discovery: true
  port_scanning: true
  endpoint_analysis: true
  vulnerability_scanning: true
  cloud_enumeration: true
  js_analysis: true
  github_dorking: true

nuclei:
  enabled: true
  severity: ["critical", "high", "medium"]
  templates: ["cves", "vulnerabilities", "misconfigurations"]

advanced_features:
  response_dedup: true
  secret_validation: true
  vuln_chaining: true
  waf_evasion: true

verification:
  enabled: true
  oob_server: "interact.sh"

burp_suite:
  enabled: false
  auto_launch: true

safety:
  confirm_before_run: true
  respect_robots_txt: true
  max_requests_per_second: 10
```

---

## 7. Safety & Stealth Architecture

```
┌──────────────────────────────────────────┐
│            SAFETY LAYER                   │
│                                          │
│  ┌────────────┐  ┌────────────────────┐  │
│  │   Scope    │  │  Rate Limiting     │  │
│  │  Validator │  │  • Adaptive delay  │  │
│  │  • In/Out  │  │  • 429/503 backoff │  │
│  │    scope   │  │  • Proxy rotation  │  │
│  │  • Wildcard│  │  • Per-host limits │  │
│  └────────────┘  └────────────────────┘  │
│                                          │
│  ┌────────────┐  ┌────────────────────┐  │
│  │   WAF      │  │  Evasion Modes     │  │
│  │  Detection │  │  • Header random   │  │
│  │  • Auto-ID │  │  • User-Agent rot  │  │
│  │  • Bypass  │  │  • Encoding loops  │  │
│  │    select  │  │  • IP rotation     │  │
│  └────────────┘  └────────────────────┘  │
│                                          │
│  ┌────────────┐  ┌────────────────────┐  │
│  │  Confirm   │  │  Graceful          │  │
│  │  Before    │  │  Shutdown           │  │
│  │  Run       │  │  (SIGINT handler)  │  │
│  └────────────┘  └────────────────────┘  │
└──────────────────────────────────────────┘
```

---

## 8. Performance Metrics

| Feature | Impact |
|:--------|:-------|
| Response Deduplication | **60% faster scans** on large sites |
| Secret Validation | **90% reduction** in false positives |
| Recursive Fuzzing | **+150% more** hidden directories found |
| Vulnerability Chaining | Auto-escalates **Medium → Critical** severity |
| Adaptive Rate Limiting | **Zero blocks** on rate-limited targets |
| Parallel Scanning | Multiple engines run concurrently |
| Tech-Aware Nuclei | Only relevant templates → faster + more accurate |

---

## 9. Codebase Statistics

| Metric | Value |
|:-------|:------|
| Total Python Modules | **60+** |
| Total Code Size | **~1 MB** |
| Scanner Modes | **13** |
| Attack Technique Modules | **11** |
| Verification Modules | **10** |
| Discovery Modules | **9** |
| Analysis Modules | **13** |
| External Tool Integrations | **12+** |
| Largest Module | `deep_scan.py` (91KB) |
| Orchestrator | `scanner.py` (1,199 lines) |

---

## 10. Roadmap & Future Enhancements

- [ ] **Automated Vulnerability Chaining Engine** — Dedicated orchestrator to auto-pipeline findings (e.g., Token Found → Auto-Try Auth Bypass). *Currently semi-manual*.
- [ ] **AI-Assisted Logic Analysis** — Integration of local LLMs to read decompiled JS/source for business logic flaws.
- [ ] **WebSocket Fuzzing** — Dedicated module for WebSocket frame manipulation and vulnerability scanning.
- [ ] **Mobile API Reconstruction** — Module to parse APK/IPA files for API endpoints (complement to web JS analysis).
- [ ] **Full Burp Suite Orchestration** — Deeper integration: auto-import findings, collaborative scan, result merge.